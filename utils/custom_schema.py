import yaml
from drf_yasg import openapi
from drf_yasg.inspectors.view import SwaggerAutoSchema
from drf_yasg.openapi import Schema
from drf_yasg.utils import force_real_str, filter_none
from drf_yasg.utils import merge_params


class YasgCustomViewSchema(SwaggerAutoSchema):
    """
    custom_swagger: 自定义 api 接口文档
    get:
      request:
        description: get 请求的描述
        parameters:
           - name: title1
             in: form/path/query 三选一
             description: title1 的描述
             description_append: '' ### title1 的补充描述
             required: true
             type: string/ integer/ boolean/ array
            - name: layer2
             in: form
             description: layer list get desc
             description_append: '' ### 可以放一些参数的补充描述信息
             required: true
             type: string
      response:
        222:
          description: layer list get 方法内部自定义响应
          response:
            examples1: [obj1, obj2, obj3 ..]
            examples2: [obj1, obj2, obj3 ..]
        404:
          description: layer list get 方法内部自定义响应
          response:
            examples1:
                      {
                          "aaa": 23333  /# 数据点的值,
                          "bbb": 0  /# 数据点是否异常(0 or 1),
                          "ccc": 1539141295  /# epoch 时间戳，可能与请求中发送的不不相等,
                      }
    post:
      request:
        description: post 请求接口描述
        parameters:
          - name: post 请求 name
            in: form
            description: post 请求 des
            required: true
            type: string
      response:
        400:
          description: post 响应外部外部400
          response:
           examples1: {
                        alert_stat_by_level: "[item1, item2, ...., ] /# item 为：{'level': 1, 'count': 13}",
                        alert_stat_by_category: "[item1, item2,.., ] /# item 为：{'category': 1, 'count': 13}",
                        alert_stat_by_time: "[item1, item2, ...,   ] /# item 为：{'time': isotime, 'count': 13}",
                        traffic_stat_by_time: "[item1, item2, . ., ] /# item 为：{'time': isotime, 'traffic': 13B}",
                        traffic_stat_by_device: "[item1, item2,.., ] /# item 为：{'device': 'plc1', 'percent': '13%'}",
                        traffic_stat_by_proto: "[item1, item2, .., ] /# item 为：{'proto': 'S7COMM', 'percent': '13%'}",
                      }
    """

    def get_all_examples(self, code_ori_res):
        """
        如果只有一个 example的话，就返回字典格式
        多个 example的话，就返回合并之后的 str 格式
        """
        r = []
        for i in range(1, 6):
            k = 'examples{}'.format(i)
            v = code_ori_res.get(k)
            if v:
                r.append(v)
        if len(r) == 1:
            return r[0]
        if len(r) > 1:
            r_ = ''
            for j in r:
                r_ += str(j) + '\n'
            return r_

        return r

    def get_doc_by_method(self):
        # 返回数据格式为 {}, 拿到具体方法需要补充的数据来源
        # 如果对应 method.__doc__中，含有 custom_swagger字段，则设为补充信息来源
        # 其次判断，view.__doc__里，若有 custom_swagger字段，则设为补充信息来源
        # 都没有自定义就返回空 {}

        view_doc = self.view.__doc__
        method = self.method.lower()
        yaml_method_doc = {}
        yaml_view_doc = {}
        yaml_path_doc = {}

        if view_doc:
            try:
                # yaml_view_doc = yaml.load(view_doc)
                yaml_view_doc = yaml.load(view_doc, Loader=yaml.FullLoader)
                if type(yaml_view_doc) is not dict:
                    yaml_view_doc = {}
            except:
                yaml_view_doc = {}

        if hasattr(self.view, method):
            method_doc = getattr(self.view, method).__doc__
        else:
            method_doc = ''

        if method_doc:
            try:
                # yaml_method_doc = yaml.load(method_doc)
                yaml_method_doc = yaml.load(method_doc, Loader=yaml.FullLoader)
                if type(yaml_method_doc) is not dict:
                    yaml_method_doc = {}
            except:
                yaml_method_doc = {}

        yaml_path_doc = self.get_doc_by_path()

        if yaml_path_doc.get('custom_swagger'):
            return yaml_path_doc

        if yaml_method_doc.get('custom_swagger'):
            return yaml_method_doc

        if yaml_view_doc.get('custom_swagger'):
            return yaml_view_doc

        return {}

    def get_ori_summary_and_description(self):
        return super(YasgCustomViewSchema, self).get_summary_and_description()

    def get_doc_by_path(self):
        # 返回数据格式为 {}, 拿到具体方法需要补充的数据来源
        ori_summary, ori_descr = self.get_ori_summary_and_description()
        yaml_path_doc = {}
        if ori_descr:
            try:
                # yaml_view_doc = yaml.load(view_doc)
                yaml_path_doc = yaml.load(ori_descr, Loader=yaml.FullLoader)
                if type(yaml_path_doc) is not dict:
                    yaml_path_doc = {}
            except:
                yaml_path_doc = {}
        return yaml_path_doc

    def check_custom_request(self):
        custom_doc = self.get_doc_by_method()
        method = self.method.lower()
        custom_doc_method = custom_doc.get(method)

        if custom_doc_method:
            custom_method_request = custom_doc_method.get('request') or None
            try:
                request_paras = custom_method_request.get('parameters')
            except:
                request_paras = None

            if request_paras:
                request_parameters = []
                for i in request_paras:
                    name = i.get('name')
                    parameter_first_description = i.get('description', '请添加描述')
                    parameter_description_append = i.get('description_append')
                    parameter_description = parameter_first_description
                    if parameter_description_append:
                        parameter_description = str(parameter_first_description) + str(parameter_description_append)

                    required = i.get('required', True)
                    p_type = i.get('type', 'string')
                    in_ = i.get('in', 'query')
                    default = i.get('default', '')
                    p = openapi.Parameter(
                        name=name,
                        in_=in_,
                        description=parameter_description,
                        type=p_type,
                        required=required,
                        default=default,
                    )
                    request_parameters.append(p)

                return request_parameters
        return None

    def get_response_serializers(self):
        custom_doc = self.get_doc_by_method()
        method = self.method.lower()
        custom_doc_method = custom_doc.get(method)

        custom_method_response = None

        if custom_doc_method:
            try:
                custom_method_response = custom_doc_method.get('response')
            except:
                custom_method_response = None

        if custom_method_response:
            # code_r = OrderedDict()
            code_r = {}

            for status_code, code_resp in custom_method_response.items():
                status_code = status_code
                code_description = code_resp.get('description', '该响应对应的描述')

                code_ori_res = code_resp.get('response', {})
                code_res_title = code_ori_res.get('title', 'titile未定义')
                code_res_description = code_ori_res.get('description', 'description未定义')
                code_res_type = code_ori_res.get('type')
                code_res_readonly = code_ori_res.get('readonly', True)
                code_res_examples = self.get_all_examples(code_ori_res)

                if code_description:
                    response_content = openapi.Response(description=code_description)
                    code_r[status_code] = response_content

                if code_description and code_res_examples:
                    examples = dict(
                        举例=code_res_examples)

                    response_content = openapi.Response(description=code_description, examples=examples)
                    code_r[status_code] = response_content

                if code_res_description and code_res_type and code_res_title:
                    r = {}
                    examples = dict(
                        举例=code_res_examples)

                    s = Schema(title=code_res_title, description=code_res_description,
                               type=code_res_type)
                    r[code_res_title] = s

                    response_schema = Schema(type='object', properties=r)
                    response_content = openapi.Response(description=code_description, schema=response_schema, examples=examples)
                    code_r[status_code] = response_content

            all_r = self.get_default_responses()
            all_r.update((str(sc), resp) for sc, resp in code_r.items())

            return all_r

        return super(YasgCustomViewSchema, self).get_response_serializers()


    def check_body_source(self):

        custom_doc = self.get_doc_by_method()
        method = self.method.lower()
        custom_doc_method = custom_doc.get(method)
        if custom_doc_method:
            if custom_doc_method.get('request'):
                if custom_doc_method.get('request').get('body_api_from_doc'):
                    return True
        else:
            return False

    def get_request_body_parameters(self,consumes):
        body_api_from_doc = self.check_body_source()
        if body_api_from_doc:
            print('body_api_from_doc', body_api_from_doc)
            return []
        else:
            return super(YasgCustomViewSchema, self).get_request_body_parameters(consumes)


    def add_manual_parameters(self, parameters):
        custom_param = self.check_custom_request()  # 如果有特殊的 params 就返回
        if custom_param:
            return merge_params(parameters, custom_param)
        return super(YasgCustomViewSchema, self).add_manual_parameters(parameters)

    def get_summary_and_description(self):
        custom_doc = self.get_doc_by_method()
        method = self.method.lower()
        custom_doc_method = custom_doc.get(method)

        api_des = None
        summary = None

        if custom_doc_method:
            if custom_doc_method.get('request') or None:
                b = custom_doc_method.get('request')
                if b.get('description') or None:
                    api_des = b.get('description') or None
                if b.get('summary'):
                    summary = b['summary']

        if api_des:
            return summary, api_des

        return super(YasgCustomViewSchema, self).get_summary_and_description()

    def get_operation(self, operation_keys=None):
        operation_keys = operation_keys or self.operation_keys
        consumes = self.get_consumes()
        produces = self.get_produces()
        body = self.get_request_body_parameters(consumes)
        query = self.get_query_parameters()
        parameters = body + query
        parameters = filter_none(parameters)
        parameters = self.add_manual_parameters(parameters)
        operation_id = self.get_operation_id(operation_keys)
        summary, description = self.get_summary_and_description()
        security = self.get_security()
        assert security is None or isinstance(security, list), "security must be a list of security requirement objects"
        deprecated = self.is_deprecated()
        tags = self.get_tags(operation_keys)
        responses = self.get_responses()

        return openapi.Operation(
            operation_id=operation_id,
            description=force_real_str(description),
            summary=force_real_str(summary),
            responses=responses,
            parameters=parameters,
            consumes=consumes,
            produces=produces,
            tags=tags,
            security=security,
            deprecated=deprecated
        )

    def get_query_parameters(self):
        natural_parameters = self.get_filter_parameters() + self.get_pagination_parameters()
        query_serializer = self.get_query_serializer()
        if query_serializer is not None:
            serializer_parameters = self.serializer_to_parameters(query_serializer, in_=openapi.IN_QUERY)

            return serializer_parameters + self.get_pagination_parameters()
        return natural_parameters
