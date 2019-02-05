#-*- coding: utf-8 -*-
import json
import logging
import math
from functools import partial
import re
import os
import urllib2, urlparse, urllib, requests

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseBadRequest, HttpResponseNotFound
from django.utils.translation import ugettext as _
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST, require_http_methods
from opaque_keys.edx.keys import AssetKey, CourseKey
from pymongo import ASCENDING, DESCENDING
from six import text_type
from xmodule.contentstore.content import StaticContent
from xmodule.contentstore.django import contentstore
from xmodule.exceptions import NotFoundError
from xmodule.modulestore.django import modulestore
from xmodule.modulestore.exceptions import ItemNotFoundError

from contentstore.utils import reverse_course_url
from contentstore.views.exception import AssetNotFoundException, AssetSizeTooLargeException
from edxmako.shortcuts import render_to_response
from openedx.core.djangoapps.contentserver.caching import del_cached_content
from student.auth import has_course_author_access
from util.date_utils import get_default_time_display
from util.json_request import JsonResponse


from django.views.decorators.csrf import csrf_exempt

__all__ = ['assets_handler', 'cdn_handler', 'cdn_callback', 'cdn_status']

REQUEST_DEFAULTS = {
    'page': 0,
    'page_size': 50,
    'sort': 'date_added',
    'direction': '',
    'asset_type': '',
    'text_search': '',
}


@login_required
@ensure_csrf_cookie
def assets_handler(request, course_key_string=None, asset_key_string=None):
    '''
    The restful handler for assets.
    It allows retrieval of all the assets (as an HTML page), as well as uploading new assets,
    deleting assets, and changing the 'locked' state of an asset.

    GET
        html: return an html page which will show all course assets. Note that only the asset container
            is returned and that the actual assets are filled in with a client-side request.
        json: returns a page of assets. The following parameters are supported:
            page: the desired page of results (defaults to 0)
            page_size: the number of items per page (defaults to 50)
            sort: the asset field to sort by (defaults to 'date_added')
            direction: the sort direction (defaults to 'descending')
            asset_type: the file type to filter items to (defaults to All)
            text_search: string to filter results by file name (defaults to '')
    POST
        json: create (or update?) an asset. The only updating that can be done is changing the lock state.
    PUT
        json: update the locked state of an asset
    DELETE
        json: delete an asset
    '''

    course_key = CourseKey.from_string(course_key_string)
    if not has_course_author_access(request.user, course_key):
        raise PermissionDenied()

    response_format = _get_response_format(request)
    if _request_response_format_is_json(request, response_format):
        if request.method == 'GET':
            return _assets_json(request, course_key)

        asset_key = AssetKey.from_string(asset_key_string) if asset_key_string else None
        return _update_asset(request, course_key, asset_key)

    elif request.method == 'GET':  # assume html
        return _asset_index(request, course_key)

    return HttpResponseNotFound()

@login_required
@ensure_csrf_cookie
def cdn_handler(request, course_key_string=None, asset_key_string=None):
    '''
    CDN 처리
    :param request:
    :param course_key_string:
    :param asset_key_string:
    :return:
    '''

    # logging.info('CDN Handler')

    course_key = CourseKey.from_string(course_key_string)
    if not has_course_author_access(request.user, course_key):
        raise PermissionDenied()

    response_format = _get_response_format(request)
    # logging.info(request);logging.info(_request_response_format_is_json(request, response_format))
    if _request_response_format_is_json(request, response_format):
        if request.method == 'GET':


            return _assets_cdn_json(request, course_key)

        asset_key = AssetKey.from_string(asset_key_string) if asset_key_string else None
        return _update_cdn_asset(request, course_key, asset_key)

    elif request.method == 'GET':  # assume html

        return _cdn_index(request, course_key)

    return HttpResponseNotFound()

@csrf_exempt
def cdn_callback(request, course_key_string=None, asset_key_string=None):

    #todo method check!!! (mme)
    try:
        course_key = CourseKey.from_string(course_key_string)

        content = request.GET
        content_keys = request.GET.keys()

        content.name = request.GET['file_name'] if 'file_name' in content_keys else ''
        content.cdn_url = request.GET['cdn_url'] if 'cdn_url' in content_keys else ''
        content.content_type = request.GET['file_type'] if 'file_type' in content_keys else ''
        content.thumbnail_location = request.GET['thumbnail_url'] if 'thumbnail_url' in content_keys else ''
        content.thumbnail_url = request.GET['thumbnail_url'] if 'thumbnail_url' in content_keys else ''
        content.location = StaticContent.compute_cdn_location(course_key, request.GET['file_name']) if 'file_name' in content_keys else ''
        content.uuid = request.GET['uuid'] if 'uuid' in content_keys else ''
        content.playtime = request.GET['playtime'] if 'playtime' in content_keys else ''
        content.state = request.GET['state'] if 'state' in content_keys else 'F'
        content.mme = 'mme'

        if content.name and content.cdn_url and content.content_type and content.thumbnail_url \
            and content.uuid and content.state:

            content.location = StaticContent.compute_cdn_location(course_key, content.name)
            # logging.info(content.location)
            mongo = contentstore().find_cdn_uuid(content.location)



            # logging.info(dir(mongo))
            # for k, v in mongo.items():
            #     logging.info(k)
            #     logging.info(v)
            if mongo['uuid'] == content.uuid:
            # # print mongo
                contentstore().save_cdn(content)
                # contentstore().update_state(content, content.state)
            #
                return JsonResponse({'status': 'ok'})
            else:
                return JsonResponse({'status': 'fail', 'msg': 'uuid not found'})
            return JsonResponse({'status': 'ok'})
        else:
            return JsonResponse({'state': 'fail', 'msg': 'params'})
    except Exception as e:

        return JsonResponse({'state': 'fail', 'msg': e.message})

# @login_required
@csrf_exempt
def cdn_status(request, course_key_string=None, asset_key_string=None):
    '''
    CDN MME
    todo 이후 로그인으로 변경함.
    :param request:
    :param course_key_string:
    :param asset_key_string:
    :return:
    '''
    course_key = CourseKey.from_string(course_key_string)
    if not has_course_author_access(request.user, course_key):
        raise PermissionDenied()
    asset_key = AssetKey.from_string(asset_key_string) if asset_key_string else None

    uuid = request.GET.get('uuid', '')
    file_name = request.GET.get('file_name', '')
    file_type = request.GET.get('file_type', '')
    thumbnail_url = request.GET.get('thumbnail_url', '')
    cdn_url = request.GET.get('cdn_url', '')
    state = request.GET.get('state')

    if uuid:
        try:
            mme_url = "http://%s/upload_mov" % urlparse.urlparse(cdn_url).netloc
        except Exception as e:
            logging.error("urlparse Error: %s" % e)
            mme_url = None

        if mme_url is None:
            logging.error('트랜스코딩 상태체크 URL이 없습니다.', request.GET)
            # return JsonResponse({'status': 'fail', 'result': None})
            # return HttpResponseNotFound()
        else:
            try:
                response = requests.get(
                    url=mme_url,
                    params={
                        uuid: uuid
                    },
                ).json()
                return JsonResponse({'status': True, 'result': response})


            except requests.exceptions.RequestException:
                logging.error('트랜스코딩 상태체크 실패', request.GET)
                # return JsonResponse({'status': 'fail', 'result': None})


        return JsonResponse({'status': False, 'result': {'uuid': uuid, 'file_name': file_name, 'file_type': file_type,
                                                          'thumbnail_url': thumbnail_url, 'cdn_url': cdn_url,
                                                          'mme_url': mme_url, 'state': state}})

    else:
        return JsonResponse({'status': False, 'result': {'uuid': uuid, 'file_name': file_name, 'file_type': file_type,
                                                          'thumbnail_url': thumbnail_url, 'cdn_url': cdn_url,
                                                          'state': state}})



def _get_response_format(request):
    return request.GET.get('format') or request.GET.get('format') or 'html'


def _request_response_format_is_json(request, response_format):
    return response_format == 'json' or 'application/json' in request.META.get('HTTP_ACCEPT', 'application/json')


def _asset_index(request, course_key):
    '''
    Display an editable asset library.

    Supports start (0-based index into the list of assets) and max query parameters.
    '''
    course_module = modulestore().get_course(course_key)

    return render_to_response('asset_index.html', {
        'language_code': request.LANGUAGE_CODE,
        'context_course': course_module,
        'max_file_size_in_mbs': settings.MAX_ASSET_UPLOAD_FILE_SIZE_IN_MB,
        'chunk_size_in_mbs': settings.UPLOAD_CHUNK_SIZE_IN_MB,
        'max_file_size_redirect_url': settings.MAX_ASSET_UPLOAD_FILE_SIZE_URL,
        'asset_callback_url': reverse_course_url('assets_handler', course_key)
    })

def _cdn_index(request, course_key):
    '''
    MME
    :param request:
    :param course_key:
    :return:
    '''
    course_module = modulestore().get_course(course_key)

    return render_to_response('cdn_index.html', {
        'language_code': request.LANGUAGE_CODE,
        'context_course': course_module,
        'max_file_size_in_mbs': settings.MAX_ASSET_UPLOAD_FILE_SIZE_IN_MB,
        'chunk_size_in_mbs': settings.UPLOAD_CHUNK_SIZE_IN_MB,
        'max_file_size_redirect_url': settings.MAX_ASSET_UPLOAD_FILE_SIZE_URL,
        'asset_callback_url': reverse_course_url('cdn_handler', course_key)
    })



def _assets_json(request, course_key):
    '''
    Display an editable asset library.

    Supports start (0-based index into the list of assets) and max query parameters.
    '''
    request_options = _parse_request_to_dictionary(request)

    filter_parameters = {}

    if request_options['requested_asset_type']:
        filters_are_invalid_error = _get_error_if_invalid_parameters(request_options['requested_asset_type'])

        if filters_are_invalid_error is not None:
            return filters_are_invalid_error

        filter_parameters.update(_get_content_type_filter_for_mongo(request_options['requested_asset_type']))

    if request_options['requested_text_search']:
        filter_parameters.update(_get_displayname_search_filter_for_mongo(request_options['requested_text_search']))

    sort_type_and_direction = _get_sort_type_and_direction(request_options)

    requested_page_size = request_options['requested_page_size']
    current_page = _get_current_page(request_options['requested_page'])
    first_asset_to_display_index = _get_first_asset_index(current_page, requested_page_size)

    query_options = {
        'current_page': current_page,
        'page_size': requested_page_size,
        'sort': sort_type_and_direction,
        'filter_params': filter_parameters
    }

    assets, total_count = _get_assets_for_page(course_key, query_options)

    if request_options['requested_page'] > 0 and first_asset_to_display_index >= total_count and total_count > 0:
        _update_options_to_requery_final_page(query_options, total_count)
        current_page = query_options['current_page']
        first_asset_to_display_index = _get_first_asset_index(current_page, requested_page_size)
        assets, total_count = _get_assets_for_page(course_key, query_options)

    last_asset_to_display_index = first_asset_to_display_index + len(assets)

    # '''
    # kmooc MME
    # asset에 CDN관련 assets처리
    # '''
    # url_split = request.META.get('HTTP_REFERER').split("/")
    # if 'cdn' in url_split:
    #     assets_in_json_format = _get_assets_cdn_in_json_format(request, assets, course_key)
    #     logging.info(assets_in_json_format)
    #
    # else:
    #     assets_in_json_format = _get_assets_in_json_format(assets, course_key)

    assets_in_json_format = _get_assets_in_json_format(assets, course_key)

    response_payload = {
        'start': first_asset_to_display_index,
        'end': last_asset_to_display_index,
        'page': current_page,
        'pageSize': requested_page_size,
        'totalCount': total_count,
        'assets': assets_in_json_format,
        'sort': request_options['requested_sort'],
        'direction': request_options['requested_sort_direction'],
        'assetTypes': _get_requested_file_types_from_requested_filter(request_options['requested_asset_type']),
        'textSearch': request_options['requested_text_search'],
    }

    return JsonResponse(response_payload)

def _assets_cdn_json(request, course_key):
    '''
    CDN 처리
    :param request:
    :param course_key:
    :return:
    '''
    request_options = _parse_request_to_dictionary(request)

    filter_parameters = {}

    if request_options['requested_asset_type']:
        filters_are_invalid_error = _get_error_if_invalid_parameters(request_options['requested_asset_type'])

        if filters_are_invalid_error is not None:
            return filters_are_invalid_error

        filter_parameters.update(_get_content_type_filter_for_mongo(request_options['requested_asset_type']))

    if request_options['requested_text_search']:
        filter_parameters.update(_get_displayname_search_filter_for_mongo(request_options['requested_text_search']))

    sort_type_and_direction = _get_sort_type_and_direction(request_options)

    # requested_page_size = request_options['requested_page_size']
    requested_page_size = request_options['requested_page_size']
    current_page = _get_current_page(request_options['requested_page'])
    first_asset_to_display_index = _get_first_asset_index(current_page, requested_page_size)

    query_options = {
        'current_page': current_page,
        'page_size': requested_page_size,
        'sort': sort_type_and_direction,
        'filter_params': filter_parameters
    }

    assets, total_count = _get_cdn_assets_for_page(course_key, query_options)

    if request_options['requested_page'] > 0 and first_asset_to_display_index >= total_count and total_count > 0:
        _update_options_to_requery_final_page(query_options, total_count)
        current_page = query_options['current_page']
        first_asset_to_display_index = _get_first_asset_index(current_page, requested_page_size)
        # assets, total_count = _get_assets_for_page(course_key, query_options)
        assets, total_count = _get_cdn_assets_for_page(course_key, query_options)

    last_asset_to_display_index = first_asset_to_display_index + len(assets)

    assets_in_json_format = _get_assets_cdn_in_json_format(request, assets, course_key)

    # logging.info(assets_in_json_format)

    response_payload = {
        'start': first_asset_to_display_index,
        'end': last_asset_to_display_index,
        'page': current_page,
        'pageSize': requested_page_size,
        'totalCount': total_count,
        'assets': assets_in_json_format,
        'sort': request_options['requested_sort'],
        'direction': request_options['requested_sort_direction'],
        'assetTypes': _get_requested_file_types_from_requested_filter(request_options['requested_asset_type']),
        'textSearch': request_options['requested_text_search'],
    }

    return JsonResponse(response_payload)


def _parse_request_to_dictionary(request):
    return {
        'requested_page': int(_get_requested_attribute(request, 'page')),
        'requested_page_size': int(_get_requested_attribute(request, 'page_size')),
        'requested_sort': _get_requested_attribute(request, 'sort'),
        'requested_sort_direction': _get_requested_attribute(request, 'direction'),
        'requested_asset_type': _get_requested_attribute(request, 'asset_type'),
        'requested_text_search': _get_requested_attribute(request, 'text_search'),
    }


def _get_requested_attribute(request, attribute):
    return request.GET.get(attribute, REQUEST_DEFAULTS.get(attribute))


def _get_error_if_invalid_parameters(requested_filter):
    requested_file_types = _get_requested_file_types_from_requested_filter(requested_filter)
    invalid_filters = []

    # OTHER is not described in the settings file as a filter
    all_valid_file_types = set(_get_files_and_upload_type_filters().keys())
    all_valid_file_types.add('OTHER')

    for requested_file_type in requested_file_types:
        if requested_file_type not in all_valid_file_types:
            invalid_filters.append(requested_file_type)

    if invalid_filters:
        error_message = {
            'error_code': 'invalid_asset_type_filter',
            'developer_message': 'The asset_type parameter to the request is invalid. '
                                 'The {} filters are not described in the settings.FILES_AND_UPLOAD_TYPE_FILTERS '
                                 'dictionary.'.format(invalid_filters)
        }
        return JsonResponse({'error': error_message}, status=400)


def _get_content_type_filter_for_mongo(requested_filter):
    """
    Construct and return pymongo query dict for the given content type categories.
    """
    requested_file_types = _get_requested_file_types_from_requested_filter(requested_filter)
    type_filter = {
        "$or": []
    }

    if 'OTHER' in requested_file_types:
        type_filter["$or"].append(_get_mongo_expression_for_type_other())
        requested_file_types.remove('OTHER')

    type_filter["$or"].append(_get_mongo_expression_for_type_filter(requested_file_types))

    return type_filter


def _get_mongo_expression_for_type_other():
    """
    Construct and return pymongo expression dict for the 'OTHER' content type category.
    """
    content_types = [ext for extensions in _get_files_and_upload_type_filters().values() for ext in extensions]
    return {
        'contentType': {
            '$nin': content_types
        }
    }


def _get_mongo_expression_for_type_filter(requested_file_types):
    """
    Construct and return pymongo expression dict for the named content type categories.

    The named content categories are the keys of the FILES_AND_UPLOAD_TYPE_FILTERS setting that are not 'OTHER':
    'Images', 'Documents', 'Audio', and 'Code'.
    """
    content_types = []
    files_and_upload_type_filters = _get_files_and_upload_type_filters()

    for requested_file_type in requested_file_types:
        content_types.extend(files_and_upload_type_filters[requested_file_type])

    return {
        'contentType': {
            '$in': content_types
        }
    }


def _get_displayname_search_filter_for_mongo(text_search):
    """
    Return a pymongo query dict for the given search string, using case insensitivity.
    """
    filters = []

    text_search_tokens = text_search.split()

    for token in text_search_tokens:
        escaped_token = re.escape(token)

        filters.append({
            'displayname': {
                '$regex': escaped_token,
                '$options': 'i',
            },
        })

    return {
        '$and': filters,
    }


def _get_files_and_upload_type_filters():
    return settings.FILES_AND_UPLOAD_TYPE_FILTERS


def _get_requested_file_types_from_requested_filter(requested_filter):
    return requested_filter.split(',') if requested_filter else []


def _get_sort_type_and_direction(request_options):
    sort_type = _get_mongo_sort_from_requested_sort(request_options['requested_sort'])
    sort_direction = _get_sort_direction_from_requested_sort(request_options['requested_sort_direction'])
    return [(sort_type, sort_direction)]


def _get_mongo_sort_from_requested_sort(requested_sort):
    if requested_sort == 'date_added':
        sort = 'uploadDate'
    elif requested_sort == 'display_name':
        sort = 'displayname'
    else:
        sort = requested_sort
    return sort


def _get_sort_direction_from_requested_sort(requested_sort_direction):
    if requested_sort_direction.lower() == 'asc':
        return ASCENDING

    return DESCENDING


def _get_current_page(requested_page):
    return max(requested_page, 0)


def _get_first_asset_index(current_page, page_size):
    return current_page * page_size


def _get_assets_for_page(course_key, options):
    current_page = options['current_page']
    page_size = options['page_size']
    sort = options['sort']
    filter_params = options['filter_params'] if options['filter_params'] else None
    start = current_page * page_size
    return contentstore().get_all_content_for_course(
        course_key, start=start, maxresults=page_size, sort=sort, filter_params=filter_params
    )

def _get_cdn_assets_for_page(course_key, options):
    current_page = options['current_page']
    page_size = options['page_size']
    sort = options['sort']
    filter_params = options['filter_params'] if options['filter_params'] else None
    start = current_page * page_size
    # return contentstore().get_all_content_for_course(
    #     course_key, start=start, maxresults=5, sort=sort, filter_params=filter_params
    # )
    return contentstore().get_all_cdn_content_for_course(
        course_key, start=start, maxresults=page_size, sort=sort, filter_params=filter_params
    )


def _update_options_to_requery_final_page(query_options, total_asset_count):
    query_options['current_page'] = int(math.floor((total_asset_count - 1) / query_options['page_size']))


def _get_assets_in_json_format(assets, course_key):
    assets_in_json_format = []
    for asset in assets:
        thumbnail_asset_key = _get_thumbnail_asset_key(asset, course_key)
        asset_is_locked = asset.get('locked', False)

        asset_in_json = _get_asset_json(
            asset['displayname'],
            asset['contentType'],
            asset['uploadDate'],
            asset['asset_key'],
            thumbnail_asset_key,
            asset_is_locked
        )

        assets_in_json_format.append(asset_in_json)

    return assets_in_json_format

def _get_assets_cdn_in_json_format(request, assets, course_key):
    '''
    MME CDN assets 파라미터 처리(json)
    :param assets:
    :param course_key:
    :return: json
    '''
    assets_in_json_format = []
    for asset in assets:

        asset['displayname'],
        asset['contentType'],

        uuid = asset.get('uuid', '')
        playtime = asset.get('playtime', '')
        state = asset.get('state', '')
        cdn_url = asset.get('cdn_url', '')


        get_thumbnail_url = asset.get('thumbnail_url', None)
        if get_thumbnail_url is None:
            if cdn_url:
                cdn_sp = cdn_url[:cdn_url.rfind('.')]
                cdn_name = os.path.basename(cdn_sp)
                thumbnail_url = os.path.join(cdn_sp.replace(cdn_name, ''), 'thumb', cdn_name + '_0.png')
            else:
                thumbnail_url = ''
        else:
            thumbnail_url = get_thumbnail_url

        ''' 상태변환 처리 '''
        if state not in ('F'):

            try:
                cdn_parse = urlparse.urlparse(cdn_url)
                mme_url = "http://%s" % cdn_parse.netloc
            except Exception as e:
                logging.log("urlparse Error: %s" % e)
                cdn_parse = ''
                mme_url = "-"

            # print content
            # print uuid

            try:
                trans_state = status_check(mme_url, uuid, playtime)
            except:
                trans_state = 'I'

            if trans_state == 'E' or trans_state == 'F':
                ''' 데이터 갱신함.'''
                # print '++++++++++++'
                # print asset

                content = request.GET

                content.name = asset['displayname']
                content.cdn_url = cdn_url
                content.url = cdn_url
                content.content_type = asset['contentType']
                content.thumbnail_location = thumbnail_url
                content.thumbnail_url = thumbnail_url
                content.location = StaticContent.compute_cdn_location(course_key, asset['displayname'])
                # content.location = asset['filename']
                content.uuid = uuid
                content.playtime = playtime
                content.state = trans_state
                content.mme = 'mme'

                state_update = contentstore().save_cdn(
                    content
                )

        else:
            trans_state = state  # 완료와 실패 이외의 상태는 등록시 설정된 값으로 구성된다.

        external_url = cdn_url



        thumbnail_asset_key = _get_thumbnail_asset_key(asset, course_key)
        asset_is_locked = asset.get('locked', False)

        asset_in_json = _get_asset_cdn_json(
            asset['displayname'],
            asset['contentType'],
            asset['uploadDate'],
            asset['asset_key'],

            uuid, playtime, state, cdn_url, thumbnail_url,

            thumbnail_asset_key,
            asset_is_locked
        )

        # logging.info(state)
        # logging.info(asset_in_json)
        assets_in_json_format.append(asset_in_json)

    return assets_in_json_format


def update_course_run_asset(course_key, upload_file):
    course_exists_response = _get_error_if_course_does_not_exist(course_key)

    if course_exists_response is not None:
        return course_exists_response

    file_metadata = _get_file_metadata_as_dictionary(upload_file)

    is_file_too_large = _check_file_size_is_too_large(file_metadata)
    if is_file_too_large:
        error_message = _get_file_too_large_error_message(file_metadata['filename'])
        raise AssetSizeTooLargeException(error_message)

    content, temporary_file_path = _get_file_content_and_path(file_metadata, course_key)

    (thumbnail_content, thumbnail_location) = contentstore().generate_thumbnail(content,
                                                                                tempfile_path=temporary_file_path)

    # delete cached thumbnail even if one couldn't be created this time (else the old thumbnail will continue to show)
    del_cached_content(thumbnail_location)

    if _check_thumbnail_uploaded(thumbnail_content):
        content.thumbnail_location = thumbnail_location

    contentstore().save(content)
    del_cached_content(content.location)

    return content


@require_POST
@ensure_csrf_cookie
@login_required
def _upload_asset(request, course_key):
    course_exists_error = _get_error_if_course_does_not_exist(course_key)

    if course_exists_error is not None:
        return course_exists_error

    # compute a 'filename' which is similar to the location formatting, we're
    # using the 'filename' nomenclature since we're using a FileSystem paradigm
    # here. We're just imposing the Location string formatting expectations to
    # keep things a bit more consistent
    upload_file = request.FILES['file']

    try:
        content = update_course_run_asset(course_key, upload_file)
    except AssetSizeTooLargeException as exception:
        return JsonResponse({'error': text_type(exception)}, status=413)

    # readback the saved content - we need the database timestamp
    readback = contentstore().find(content.location)
    locked = getattr(content, 'locked', False)
    return JsonResponse({
        'asset': _get_asset_json(
            content.name,
            content.content_type,
            readback.last_modified_at,
            content.location,
            content.thumbnail_location,
            locked
        ),
        'msg': _('Upload completed')
    })


def _get_error_if_course_does_not_exist(course_key):
    try:
        modulestore().get_course(course_key)
    except ItemNotFoundError:
        logging.error('Could not find course: %s', course_key)
        return HttpResponseBadRequest()


def _get_file_metadata_as_dictionary(upload_file):
    # compute a 'filename' which is similar to the location formatting; we're
    # using the 'filename' nomenclature since we're using a FileSystem paradigm
    # here; we're just imposing the Location string formatting expectations to
    # keep things a bit more consistent
    return {
        'upload_file': upload_file,
        'filename': upload_file.name,
        'mime_type': upload_file.content_type,
        'upload_file_size': get_file_size(upload_file)
    }


def get_file_size(upload_file):
    # can be used for mocking test file sizes.
    return upload_file.size


def _check_file_size_is_too_large(file_metadata):
    upload_file_size = file_metadata['upload_file_size']
    maximum_file_size_in_megabytes = settings.MAX_ASSET_UPLOAD_FILE_SIZE_IN_MB
    maximum_file_size_in_bytes = maximum_file_size_in_megabytes * 1000 ** 2

    return upload_file_size > maximum_file_size_in_bytes


def _get_file_too_large_error_message(filename):
    return _(
        'File {filename} exceeds maximum size of '
        '{maximum_size_in_megabytes} MB.'
    ).format(
        filename=filename,
        maximum_size_in_megabytes=settings.MAX_ASSET_UPLOAD_FILE_SIZE_IN_MB,
    )


def _get_file_content_and_path(file_metadata, course_key):
    content_location = StaticContent.compute_location(course_key, file_metadata['filename'])
    upload_file = file_metadata['upload_file']

    file_can_be_chunked = upload_file.multiple_chunks()

    static_content_partial = partial(StaticContent, content_location, file_metadata['filename'],
                                     file_metadata['mime_type'])

    if file_can_be_chunked:
        content = static_content_partial(upload_file.chunks())
        temporary_file_path = upload_file.temporary_file_path()
    else:
        content = static_content_partial(upload_file.read())
        temporary_file_path = None
    return content, temporary_file_path


def _check_thumbnail_uploaded(thumbnail_content):
    return thumbnail_content is not None


def _get_thumbnail_asset_key(asset, course_key):
    # note, due to the schema change we may not have a 'thumbnail_location' in the result set
    thumbnail_location = asset.get('thumbnail_location', None)
    thumbnail_asset_key = None

    if thumbnail_location:
        thumbnail_path = thumbnail_location[4]
        thumbnail_asset_key = course_key.make_asset_key('thumbnail', thumbnail_path)
    return thumbnail_asset_key


@require_http_methods(('DELETE', 'POST', 'PUT'))
@login_required
@ensure_csrf_cookie
def _update_asset(request, course_key, asset_key):
    '''
    restful CRUD operations for a course asset.
    Currently only DELETE, POST, and PUT methods are implemented.

    asset_path_encoding: the odd /c4x/org/course/category/name repr of the asset (used by Backbone as the id)
    '''
    if request.method == 'DELETE':
        try:
            delete_asset(course_key, asset_key)
            return JsonResponse()
        except AssetNotFoundException:
            return JsonResponse(status=404)

    elif request.method in ('PUT', 'POST'):
        if 'file' in request.FILES:
            return _upload_asset(request, course_key)

        # update existing asset
        try:
            modified_asset = json.loads(request.body)
        except ValueError:
            return HttpResponseBadRequest()
        contentstore().set_attr(asset_key, 'locked', modified_asset['locked'])
        # delete the asset from the cache so we check the lock status the next time it is requested.
        del_cached_content(asset_key)
        return JsonResponse(modified_asset, status=201)

@require_http_methods(('DELETE', 'POST', 'PUT'))
@login_required
@ensure_csrf_cookie
def _update_cdn_asset(request, course_key, asset_key):
    '''
    CDN MME
    :param request:
    :param course_key:
    :param asset_key:
    :return:
    '''

    if request.method in ('PUT', 'POST'):
        # if 'file' in request.FILES:
        #     return _upload_asset(request, course_key)
        # logging.info(request.GET)
        if 'cdn_url' in request.GET:

            return _save_cdn(request, course_key)

        # update existing asset
        try:
            modified_asset = json.loads(request.body)
        except ValueError:
            return HttpResponseBadRequest()
        contentstore().set_attr(asset_key, 'locked', modified_asset['locked'])
        # delete the asset from the cache so we check the lock status the next time it is requested.
        del_cached_content(asset_key)
        return JsonResponse(modified_asset, status=201)

    if request.method == 'DELETE':
        try:


            # try:
            ''' MME 콘텐츠 삭제'''
            content = contentstore().find_cdn_uuid(asset_key)

            uuid = content['uuid']
            playtime = content['playtime']
            cdn_url = content['cdn_url']
            cdn_parse = urlparse.urlparse(cdn_url)

            # print content
            # print uuid
            mme_url = "http://%s" % cdn_parse.netloc

            if uuid is None or uuid == '':
                uuid = cdn_url.split("/")[-1].replace(".mp4", "")

            # print "mme delete"

            mme_delete(mme_url, uuid)
            # except Exception, e:
            #     print "MME Delete Exception: %s" % e

            # print "mme delete finish"

            # print "mongo delete"
            delete_asset(course_key, asset_key)
            # print "mongo delete finish"

            return JsonResponse()
        except AssetNotFoundException:
            return JsonResponse(status=404)
    elif request.method in ('PUT', 'POST'):
        if 'cdn_url' in request.GET:
            ''' kmooc MME'''
            return _save_cdn(request, course_key)
        else:
            # Update existing asset
            try:
                modified_asset = json.loads(request.body)
            except ValueError:
                return HttpResponseBadRequest()
            contentstore().set_attr(asset_key, 'locked', modified_asset['locked'])
            # Delete the asset from the cache so we check the lock status the next time it is requested.
            del_cached_content(asset_key)
            return JsonResponse(modified_asset, status=201)


def _save_cdn(request, course_key):
    '''
    CDN MME
    메소드 추가
    '''

    content = request.GET
    content.name = request.GET['file_name']

    try:
        req_cdn_url = content.cdn_url.replace("mme.", "vod.")
        content.cdn_url = req_cdn_url
        content.url = req_cdn_url
    except:
        try:
            content.cdn_url = request.GET['cdn_url']
        except:
            content.cdn_url = '-'

    logging.info(request.GET)
    logging.info(content)


    content.content_type = request.GET['file_type']
    content.thumbnail_location = request.GET['thumbnail_url'] or ''
    content.thumbnail_url = request.GET['thumbnail_url'] or ''
    content.location = StaticContent.compute_cdn_location(course_key, request.GET['file_name'])
    # print content

    try:
        content.uuid = content.uuid
        content.playtime = content.playtime
        content.state = content.state
        content.mme = content.mme
    except:
        content.uuid = ''
        content.playtime = ''
        content.state = ''
        content.mme = ''

    contentstore().save_cdn(content)

    readback = contentstore().find_cdn(content.location)
    locked = False;
    response_payload = {
        'asset': _get_asset_json(
            content.name,
            content.content_type,
            readback.last_modified_at,
            content.location,
            content.thumbnail_location,
            locked
        ),
        'msg': _('Upload completed'),
        'result': 'success'
    }


    return JsonResponse(response_payload)


def _callback_cdn(request, course_key):
    '''
    CDN MME
    메소드 추가
    '''

    content_keys = request.GET.keys()

    content = request.GET
    content.name = request.GET['file_name']

    content.name = request.GET['file_name'] if 'file_name' in content_keys else ''
    content.cdn_url = request.GET['cdn_url'] if 'cdn_url' in content_keys else ''
    content.content_type = request.GET['file_type'] if 'file_type' in content_keys else ''
    content.thumbnail_location = request.GET['thumbnail_url'] if 'thumbnail_url' in content_keys else ''
    content.thumbnail_url = request.GET['thumbnail_url'] if 'thumbnail_url' in content_keys else ''
    content.location = StaticContent.compute_cdn_location(course_key, request.GET[
        'file_name']) if 'file_name' in content_keys else ''
    content.uuid = request.GET['uuid'] if 'uuid' in content_keys else ''
    content.playtime = request.GET['playtime'] if 'playtime' in content_keys else ''
    content.state = request.GET['state'] if 'state' in content_keys else 'F'


    content.content_type = request.GET['file_type']
    content.thumbnail_location = request.GET['thumbnail_url'] or ''
    content.thumbnail_url = request.GET['thumbnail_url'] or ''
    content.location = StaticContent.compute_cdn_location(course_key, request.GET['file_name'])
    # print content

    contentstore().save_cdn(content)

    readback = contentstore().find_cdn(content.location)
    locked = False;
    response_payload = {
        'asset': _get_asset_json(
            content.name,
            content.content_type,
            readback.last_modified_at,
            content.location,
            content.thumbnail_location,
            locked
        ),
        'msg': _('Upload completed'),
        'result': 'success'
    }


    return JsonResponse(response_payload)


def _save_content_to_trash(content):
    contentstore('trashcan').save(content)


def delete_asset(course_key, asset_key):
    content = _check_existence_and_get_asset_content(asset_key)

    _save_content_to_trash(content)

    _delete_thumbnail(content.thumbnail_location, course_key, asset_key)
    contentstore().delete(content.get_id())
    del_cached_content(content.location)


def _check_existence_and_get_asset_content(asset_key):
    try:
        content = contentstore().find(asset_key)
        return content
    except NotFoundError:
        raise AssetNotFoundException


def _delete_thumbnail(thumbnail_location, course_key, asset_key):
    if thumbnail_location is not None:

        # We are ignoring the value of the thumbnail_location-- we only care whether
        # or not a thumbnail has been stored, and we can now easily create the correct path.
        thumbnail_location = course_key.make_asset_key('thumbnail', asset_key.block_id)

        try:
            thumbnail_content = contentstore().find(thumbnail_location)
            _save_content_to_trash(thumbnail_content)
            contentstore().delete(thumbnail_content.get_id())
            del_cached_content(thumbnail_location)
        except Exception:  # pylint: disable=broad-except
            logging.warning('Could not delete thumbnail: %s', thumbnail_location)


def _get_asset_json(display_name, content_type, date, location, thumbnail_location, locked):
    '''
    Helper method for formatting the asset information to send to client.
    '''
    asset_url = StaticContent.serialize_asset_key_with_slash(location)
    external_url = settings.LMS_BASE + asset_url
    return {
        'display_name': display_name,
        'content_type': content_type,
        'date_added': get_default_time_display(date),
        'url': asset_url,
        'external_url': external_url,
        'portable_url': StaticContent.get_static_path_from_location(location),
        'thumbnail': StaticContent.serialize_asset_key_with_slash(thumbnail_location) if thumbnail_location else None,
        'locked': locked,
        # needed for Backbone delete/update.
        'id': unicode(location)
    }


def _get_asset_cdn_json(display_name, content_type, date, location, uuid, playtime, state, cdn_url, thumbnail_url, thumbnail_location, locked):
    '''
    Helper method for formatting the asset information to send to client.
    '''
    asset_url = StaticContent.serialize_asset_key_with_slash(location)
    return {
        'display_name': display_name,
        'content_type': content_type,
        'date_added': get_default_time_display(date),
        'url': state,
        'external_url': cdn_url,
        'portable_url': uuid,
        'uuid': uuid, 'playtime': playtime, 'state': state, 'cdn_url': cdn_url, 'thumbnail_url': thumbnail_url,
        'thumbnail': thumbnail_url,
        'locked': locked,
        # needed for Backbone delete/update.
        'id': unicode(location)
    }

def _get_cdn_json(display_name, content_type, date, location, thumbnail_location, cdn_url='', uuid='', playtime='', state=''):
    '''
    kmooc MME
    '''
    asset_url = StaticContent.serialize_asset_key_with_slash(location)
    localtime = date.strftime("%Y-%m-%d")

    # external_url = settings.LMS_BASE + asset_url

    return {
        'display_name': display_name,
        'content_type': content_type,
        'date_added': get_default_time_display(date),
        # 'date_added': localtime,
        'url': uuid,
        # 'url': uuid,
        'external_url': cdn_url,
        # 'portable_url': StaticContent.get_static_path_from_location(location),
        'portable_url': state,
        'thumbnail': thumbnail_location,
        'uuid': uuid,
        'playtime': playtime,
        'state': state,
        # 'locked': locked,
        'id': unicode(location)
    }

def mme_delete(mme, uuid):
    '''
    MME 에 저장된 영상 삭제
    '''
    try:

        content_delete_host = "%s/mov_delete?uuid=%s" % (mme, uuid)
        # print content_delete_host
        header = {'User-Agent': 'MME/2.0', 'Content-Type': 'application/json'}
        req = urllib2.Request(content_delete_host)
        res = urllib2.urlopen(req, timeout=2).read()
        # print 'MME CDN DELETE: %s' % content_delete_host
        # print res

        # logging.info({'url': content_delete_host, 'result': res})

        return True
    except urllib2.HTTPError, e:
        print "HTTPError: %s" % e
        return False
    except urllib2.URLError, e:
        print "URLError: %s" % e
        return False
    except Exception, e:
        print "Exception: %s" %e
        return False

def status_check(mme_url, uuid, playtime):

    url = "%s/upload_mov?uuid=%s&playtime=%s" % (mme_url, uuid, playtime)
    req = urllib2.Request(url)
    res = urllib2.urlopen(req).read()


    j_data = json.loads(res)
    if j_data['data']['status'] == 'complete':
        state = 'E'
    elif j_data['data']['status'] == 'fail':
        state = 'F'

    return state

