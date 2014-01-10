import base64
import hashlib
import hmac
import urlparse
from unittest import TestCase, main
from apysigner import Signer, get_signature


class SignatureMakerTests(TestCase):

    def setUp(self):
        self.private_key = 'CoVTr95Xv2Xlu4ZjPo2bWl7u4SnnAMAD7EFFBMS4Dy4='
        self.signature_param = "signature"
        self.signer = Signer(self.private_key)

    def test_returns_payload_qs_sorted_by_dict_keys(self):
        payload = {'one': 'first one', 'two': '2', 'three': '3', 'four': '4'}
        expected_qs = 'four=4&one=first+one&three=3&two=2'
        self.assertEqual(expected_qs, self.signer._encode_payload(payload))

    def test_returns_payload_qs_sorted_by_dict_keys_and_vals(self):
        payload = {'one': '1', 'two': '2', 'three': '3', 'four': ['8', '4', '0']}
        expected_qs = 'four_0=8&four_1=4&four_2=0&one=1&three=3&two=2'
        self.assertEqual(expected_qs, self.signer._encode_payload(payload))

    def test_returns_payload_qs_sorted_by_first_tuple_item(self):
        payload = [('one', 'first one'), ('two', '2'), ('three', '3'), ('four', '4')]
        expected_qs = 'four=4&one=first+one&three=3&two=2'
        self.assertEqual(expected_qs, self.signer._encode_payload(payload))

    def test_returns_payload_qs_sorted_by_first_tuple_item_and_vals(self):
        payload = [('one', '1'), ('two', '2'), ('three', '3'), ('four', ['8', '4', '0'])]
        expected_qs = 'four_0=8&four_1=4&four_2=0&one=1&three=3&two=2'
        self.assertEqual(expected_qs, self.signer._encode_payload(payload))

    def test_returns_payload_qs_sorted_by_first_tuple_item_and_vals_when_item_repeats(self):
        payload = {'one': '1', 'two': ['two', '2', 'dos']}
        expected_qs = 'one=1&two_0=two&two_1=2&two_2=dos'
        self.assertEqual(expected_qs, self.signer._encode_payload(payload))

    def test_returns_empty_string_when_payload_is_none_or_empty(self):
        self.assertEqual('', self.signer._encode_payload(None))
        self.assertEqual('', self.signer._encode_payload({}))
        self.assertEqual('', self.signer._encode_payload([]))
        self.assertEqual('', self.signer._encode_payload(()))
        self.assertEqual('', self.signer._encode_payload(''))

    def test_signs_request_with_data(self):
        data = {'username': 'some tester', 'first_name': 'Mr. Test'}
        signature = self.signer.create_signature('http://www.example.com/accounts/user/add/', data)

        expected_signature = '4ZAQJqmWE_C9ozPkpJ3Owh0Z_DFtYkCdi4XAc-vOLtI='
        self.assertEqual(expected_signature, signature)

    def test_signs_request_with_no_payload(self):
        signature = self.signer.create_signature('http://www.example.com/accounts/?one=1&two=2&two=dos&two=two')
        expected_signature = 'bm9_IDIQtEElubM5r__M0kDMUfdQ__0ZSI-2Bi6DcRo='
        self.assertEqual(expected_signature, signature)

    def test_signs_request_when_private_key_is_unicode(self):
        # test to ensure we handle private key properly no matter what kind of character
        # encoding the private key is given as:
        # http://bugs.python.org/issue4329  (not a bug, but this is the situation and explanation)
        signer = Signer(unicode(self.private_key))
        signature = signer.create_signature('http://www.example.com/accounts/user/add/')

        expected_signature = '2ZzgF8AGioIfYzPqedI0FfJKEDG2asRA1LR70q4IOYs='
        self.assertEqual(expected_signature, signature)

    def test_requires_private_key(self):
        with self.assertRaises(Exception) as context:
            Signer(None)

        self.assertEqual(context.exception.message, 'Private key is required.')

    def test_get_signature_creates_signature_with_payload_data(self):
        base_url = 'http://www.example.com/accounts/user/add/'
        data = {'username': 'some tester', 'first_name': 'Mr. Test'}
        signature = get_signature(self.private_key, base_url, data)

        expected_signature = '4ZAQJqmWE_C9ozPkpJ3Owh0Z_DFtYkCdi4XAc-vOLtI='
        self.assertEqual(expected_signature, signature)

    def test_get_signature_with_complex_non_unicode_payload(self):
        base_url = 'http://www.example.com/accounts/user/add/'
        data = {'coverages': [{'construction_type': u'', 'premium': None, 'fire_class': None, 'optional_coverages': [{'construction_type': u'', 'irpms': [], 'fire_class': None, 'deductible_code': u'500', 'coverage_amount': '100000', 'territory': None, 'rate_code': u'033', 'year_built': None}], 'rate_code': u'005', 'property_id': '6b86b273ff3', 'packages': [], 'year_built': None, 'coverage_amount': '100000', 'irpms': [], 'deductible_code': u'500', 'territory': None}, {'construction_type': u'', 'premium': None, 'fire_class': None, 'optional_coverages': [], 'rate_code': u'015', 'property_id': 'd4735e3a265', 'packages': [{'rate_code': u'017', 'irpms': [], 'construction_type': u'', 'deductible_code': u'500', 'fire_class': None, 'rateable_amount': 10000, 'territory': None, 'property_id': '6b86b273ff3'}], 'year_built': None, 'coverage_amount': '100000', 'irpms': [], 'deductible_code': u'500', 'territory': None}, {'construction_type': u'', 'premium': None, 'fire_class': None, 'optional_coverages': [{'construction_type': u'', 'irpms': [], 'fire_class': None, 'deductible_code': u'500', 'coverage_amount': '100000', 'territory': None, 'rate_code': u'033', 'year_built': None}], 'rate_code': u'002', 'property_id': '4e07408562b', 'packages': [], 'year_built': None, 'coverage_amount': '100000', 'irpms': [u'RCC'], 'deductible_code': u'500', 'territory': None}], 'producer': u'matt.morrison', 'policy_type': u'FM', 'policy': {'effective_date': None, 'path': 'APPS9690', 'apps_key': u'FM', 'discount_a': u'1'}, 'company': 9690, 'agency': None, 'policy_id': 1}
        signature = get_signature(self.private_key, base_url, data)
        expected_signature = 'AJfz5X9RV_1XIp4jEiUj-9pdOBj6-bPgGMgFVqb-CN0='
        self.assertEqual(expected_signature, signature)

    def test_convert_function_will_also_sort_dict_based_on_key(self):
        d = {u'coverages': [{u'construction_type': u'', u'premium': None, u'coverage_amount': u'100000', u'territory': None, u'irpms': [], u'fire_class': None, u'deductible_code': u'500', u'optional_coverages': [{u'construction_type': u'', u'year_built': None, u'coverage_amount': u'100000', u'irpms': [], u'fire_class': None, u'deductible_code': u'500', u'territory': None, u'rate_code': u'033'}], u'packages': [], u'year_built': None, u'rate_code': u'005', u'property_id': u'6b86b273ff3'}, {u'construction_type': u'', u'premium': None, u'coverage_amount': u'100000', u'territory': None, u'irpms': [], u'fire_class': None, u'deductible_code': u'500', u'optional_coverages': [], u'packages': [{u'fire_class': None, u'rate_code': u'017', u'irpms': [], u'construction_type': u'', u'deductible_code': u'500', u'rateable_amount': 10000, u'territory': None, u'property_id': u'6b86b273ff3'}], u'year_built': None, u'rate_code': u'015', u'property_id': u'd4735e3a265'}, {u'construction_type': u'', u'premium': None, u'coverage_amount': u'100000', u'territory': None, u'irpms': [u'RCC'], u'fire_class': None, u'deductible_code': u'500', u'optional_coverages': [{u'construction_type': u'', u'year_built': None, u'coverage_amount': u'100000', u'irpms': [], u'fire_class': None, u'deductible_code': u'500', u'territory': None, u'rate_code': u'033'}], u'packages': [], u'year_built': None, u'rate_code': u'002', u'property_id': u'4e07408562b'}], u'producer': u'matt.morrison', u'company': 9690, u'agency': None, u'policy_type': u'FM', u'policy': {u'effective_date': None, u'path': u'APPS9690', u'apps_key': u'FM', u'discount_a': u'1'}, u'policy_id': 1}
        unicode_payload = self.signer._flatten(d)
        d_sig = self.signer.create_signature("http://example.com", d)
        u_sig = self.signer.create_signature("http://example.com", unicode_payload)
        self.assertEqual(d_sig, u_sig)

    def test_get_signature_signs_request_with_no_payload(self):
        signature = get_signature(self.private_key, 'http://www.example.com/accounts/?one=1&two=2&two=dos&two=two')
        expected_signature = 'bm9_IDIQtEElubM5r__M0kDMUfdQ__0ZSI-2Bi6DcRo='
        self.assertEqual(expected_signature, signature)

    def test_converts_every_str_key_and_value_of_dictionary_to_unicode(self):
        d = {'my_key': 'my_value'}
        unicode_payload = self.signer._flatten(d)
        for k, v in unicode_payload.items():
            self.assertEqual(type(k), unicode)
            self.assertEqual(type(v), unicode)

    def test_converts_every_str_key_and_value_of_nested_dictionary_to_unicode(self):
        d = {'my_key': {"one": "two"}}
        unicode_payload = self.signer._flatten(d)
        for k, v in unicode_payload.items():
            self.assertEqual(type(k), unicode)
            self.assertEqual(type(v), unicode)

    def test_converts_every_str_key_and_value_of_nested_list_to_unicode(self):
        d = {'my_key': ["one", "two"]}
        unicode_payload = self.signer._flatten(d)
        self.assertEqual(type(unicode_payload['my_key_0']), unicode)
        self.assertEqual(type(unicode_payload['my_key_1']), unicode)

    def test_converts_every_str_key_and_value_of_nested_list_and_nested_dict_to_unicode(self):
        d = {'my_key': [{"one": "two"}, {"three": "four"}]}
        unicode_payload = self.signer._flatten(d)
        self.assertEqual(type(unicode_payload['my_key_0_one']), unicode)
        self.assertEqual(type(unicode_payload['my_key_1_three']), unicode)

    def test_does_not_convert_non_str_types_of_nested_dictionary_to_unicode(self):
        d = {'my_key': {"one": None}}
        unicode_payload = self.signer._flatten(d)
        self.assertEqual(unicode_payload['my_key_one'], 'null')

    def test_does_not_convert_int_types_of_nested_dictionary_to_unicode(self):
        d = {'my_key': {"one": 3}}
        unicode_payload = self.signer._flatten(d)
        for k, v in unicode_payload.items():
            self.assertEqual(type(k), unicode)
            self.assertEqual(type(v), int)

    def test_flattens_nested_dictionaries(self):
        orig = {'a': {'b': {'c': 'd'}}}
        new = self.signer._flatten(orig)
        self.assertEqual(new, {'a_b_c': 'd'})

    def test_flattens_nested_lists(self):
        orig = {'a': {'b': {'c': ['d', 'e']}}}
        new = self.signer._flatten(orig)
        self.assertEqual(new, {'a_b_c_0': 'd', 'a_b_c_1': 'e'})

    def test_flattens_dictionaries_nested_in_lists(self):
        orig = {'a': {'b': {'c': [{'d': 'e'}, {'f': 'g'}]}}}
        new = self.signer._flatten(orig)
        self.assertEqual(new, {'a_b_c_0_d': 'e', 'a_b_c_1_f': 'g'})

    def test_flattens_complex_example(self):
        orig = {'a': {'b': {'c': ({'d': 'e'}, {'f': ['1', u'2', 3]})}}}
        new = self.signer._flatten(orig)
        self.assertEqual(new, {'a_b_c_1_f_1': u'2', 'a_b_c_0_d': 'e', 'a_b_c_1_f_2': 3, 'a_b_c_1_f_0': '1'})

    def test_encodes_and_sorts_payload(self):
        base_url = 'http://imtapps.com/?a=1&b=2'
        payloads = [
            {'a': {'b': {'c': ({'d': 'e', 'a': 1, 'z': 2, 'w': 3}, {'f': ['1', u'2', 3]})}}},
            {'a': {'b': {'c': ({'z': 2, 'd': 'e', 'a': 1, 'w': 3}, {'f': ['1', u'2', 3]})}}}
        ]

        for payload in payloads:
            url = urlparse.urlparse(base_url)
            url_to_sign = url.path + '?' + url.query
            encoded_payload = self.signer._encode_payload(payload)
            self.assertEqual('a_b_c_0_a=1&a_b_c_0_d=e&a_b_c_0_w=3&a_b_c_0_z=2&a_b_c_1_f_0=1&a_b_c_1_f_1=2&a_b_c_1_f_2=3', encoded_payload)

            decoded_key = base64.urlsafe_b64decode(self.private_key.encode('utf-8'))
            signature = hmac.new(decoded_key, url_to_sign + encoded_payload, hashlib.sha256)
            result = base64.urlsafe_b64encode(signature.digest())
            self.assertEqual('280HNcfzM5k5S75NIopw-e8Y-tnQQBw3TTfVcQ3BCSc=', result)

            actual = self.signer.create_signature(base_url, payload)
            self.assertEqual(result, actual)

    def test_encodes_and_sorts_simple_payload(self):
        base_url = 'http://imtapps.com/?a=1&b=2'
        payloads = [
            {'a': [{'9': 2, '1': 0}, {'8': 3}], 'b': [{'9': 2, '1': 0}, {'7': 4, '1': 'z'}]},
            {'a': [{'1': 0, '9': 2}, {'8': 3}], 'b': [{'1': 0, '9': 2}, {'1': 'z', '7': 4}]}
        ]

        for payload in payloads:
            url = urlparse.urlparse(base_url)
            url_to_sign = url.path + '?' + url.query
            encoded_payload = self.signer._encode_payload(payload)
            self.assertEqual('a_0_1=0&a_0_9=2&a_1_8=3&b_0_1=0&b_0_9=2&b_1_1=z&b_1_7=4', encoded_payload)

            decoded_key = base64.urlsafe_b64decode(self.private_key.encode('utf-8'))
            signature = hmac.new(decoded_key, url_to_sign + encoded_payload, hashlib.sha256)
            result = base64.urlsafe_b64encode(signature.digest())
            self.assertEqual('Pq9-sYY63CPMaHL5i_Tw7ltZs4TqDvC_QHfjgLkLZeY=', result)

            actual = self.signer.create_signature(base_url, payload)
            self.assertEqual(result, actual)

    def test_payload_with_different_value_types(self):
        base_url = 'http://imtapps.com/?a=1&b=2'
        payload = {'a': [{'b': 1, 'c': '2'}, 1], 'd': 3, 'e': '4'}

        url = urlparse.urlparse(base_url)
        url_to_sign = url.path + '?' + url.query
        encoded_payload = self.signer._encode_payload(payload)
        self.assertEqual('a_0_b=1&a_0_c=2&a_1=1&d=3&e=4', encoded_payload)

        decoded_key = base64.urlsafe_b64decode(self.private_key.encode('utf-8'))
        signature = hmac.new(decoded_key, url_to_sign + encoded_payload, hashlib.sha256)
        result = base64.urlsafe_b64encode(signature.digest())
        self.assertEqual('S5CsOh-jG4Rff59COn0PV5JsmqLxTnoJ1q4Zl-w3Yyo=', result)

        actual = self.signer.create_signature(base_url, payload)
        self.assertEqual(result, actual)

    def test_does_not_add_list_index_when_only_one_item_to_handle_multi_value_dicts(self):
        base_url = 'http://imtapps.com/?a=1&b=2'
        url = urlparse.urlparse(base_url)
        url_to_sign = url.path + '?' + url.query
        payload = {'hi': ['8']}
        encoded_payload = self.signer._encode_payload(payload)
        self.assertEqual('hi=8', encoded_payload)
        decoded_key = base64.urlsafe_b64decode(self.private_key.encode('utf-8'))
        signature = hmac.new(decoded_key, url_to_sign + encoded_payload, hashlib.sha256)
        result = base64.urlsafe_b64encode(signature.digest())
        self.assertEqual('T5Lnys4I45eBWdm9NxVInosFv8gl8rt17YwvqKxAzKI=', result)

        actual = self.signer.create_signature(base_url, payload)
        self.assertEqual(result, actual)

    def test_does_not_add_list_index_when_only_one_item_and_nested_objects(self):
        base_url = 'http://imtapps.com/?a=1&b=2'
        url = urlparse.urlparse(base_url)
        url_to_sign = url.path + '?' + url.query
        payload = {"hi": {"sub": "asdf", "subwithlist": ["8"]}, "helloagain": "something"}
        encoded_payload = self.signer._encode_payload(payload)
        self.assertEqual('helloagain=something&hi_sub=asdf&hi_subwithlist=8', encoded_payload)
        decoded_key = base64.urlsafe_b64decode(self.private_key.encode('utf-8'))
        signature = hmac.new(decoded_key, url_to_sign + encoded_payload, hashlib.sha256)
        result = base64.urlsafe_b64encode(signature.digest())
        self.assertEqual('0jiGHS_BvQOBKiGO7kr0Hnsi9XpHhZ2k2Sj0vQ0Hd1Y=', result)

        actual = self.signer.create_signature(base_url, payload)
        self.assertEqual(result, actual)

    def test_big_example(self):
        base_url = 'http://imtapps.com/?a=1&b=2'
        payload = {"insured": {"id": 15288, "first_name": "CLEMENTINE", "last_name": "XXX", "name_2": "asdf", "address_1": "2885 130TH STREET", "address_2": "second address", "city": "YALE", "state": "IA", "zip_code": "502770000", "country": "USA"}, "property": {"id": 15280, "address": "Acres:     Qtr: SE Sec: 18 Twp: 81  Rng: 30", "city": "GUTHRIE", "state": "IA", "zip_code": "00000", "country": "USR", "description": "Dwelling"}, "mortgagee": {"id": 15288, "name_1": "WELLS FARGO BANK", "name_2": "FIRST AMERICAN", "address_1": "1224 1ST STREET", "address_2": "P.O. BOX 8", "city": "PERRY", "state": "IA", "zip_code": "502200000", "country": "GBR", "loan_number": "XXX", "mortgagee_type": "1ST"}, "agent": {"id": 15288, "agent_code": "yyy", "name_1": "asfd", "name_2": "SOMETHING", "address_1": "605 E. MAIN", "address_2": "P.O. BOX 99", "city": "xxx", "state": "IA", "zip_code": "999999999", "country": "XXR", "phone_number": "9999999999"}, "insurance_company": {"id": 15286, "naic_code": "00000", "name": "XYZ", "address_1": "988 WALNUT STREET, BOX 123", "address_2": "address two", "city": "XYA", "state": "IA", "zip_code": "500630624", "phone_number": "5159924121"}, "coverage_items": [{"id": 134081, "coverage_code": "O", "coverage_amount": 18, "deductible_amount": 19}, {"id": 134080, "coverage_code": "O", "coverage_amount": 16, "deductible_amount": 17}, {"id": 134079, "coverage_code": "O", "coverage_amount": 14, "deductible_amount": 15}, {"id": 134078, "coverage_code": "G", "coverage_amount": 12, "deductible_amount": 13}, {"id": 134077, "coverage_code": "F", "coverage_amount": 10, "deductible_amount": 11}, {"id": 134076, "coverage_code": "E", "coverage_amount": 8, "deductible_amount": 9}, {"id": 134075, "coverage_code": "D", "coverage_amount": 6, "deductible_amount": 7}, {"id": 134074, "coverage_code": "C", "coverage_amount": 4, "deductible_amount": 5}, {"id": 134073, "coverage_code": "B", "coverage_amount": 2, "deductible_amount": 3}, {"id": 134072, "coverage_code": "A", "coverage_amount": 165000, "deductible_amount": 500}], "additional_information": {"id": 15288, "premium_amount": "99999.99", "increase_premium": "11111.11", "due_date": "2010-09-29", "escrow": False}, "id": 15318, "transaction_id": "201009290000002", "policy_id": "00183", "created": "2010-09-29", "reason": "AM", "activated": "2010-01-20", "effective": "2010-01-20", "expired": "2011-01-20", "policy_type_code": "19", "loaded": "2014-01-07T01:02:27.302", "received": None, "send": True, "batch_id": "a9ec0efe-7769-11e3-91e3-005056993634", "company": "Demo Company", "status": "", "error_message": ""}

        url = urlparse.urlparse(base_url)
        url_to_sign = url.path + '?' + url.query
        encoded_payload = self.signer._encode_payload(payload)
        self.assertEqual('activated=2010-01-20&additional_information_due_date=2010-09-29&additional_information_escrow=false&additional_information_id=15288&additional_information_increase_premium=11111.11&additional_information_premium_amount=99999.99&agent_address_1=605+E.+MAIN&agent_address_2=P.O.+BOX+99&agent_agent_code=yyy&agent_city=xxx&agent_country=XXR&agent_id=15288&agent_name_1=asfd&agent_name_2=SOMETHING&agent_phone_number=9999999999&agent_state=IA&agent_zip_code=999999999&batch_id=a9ec0efe-7769-11e3-91e3-005056993634&company=Demo+Company&coverage_items_0_coverage_amount=18&coverage_items_0_coverage_code=O&coverage_items_0_deductible_amount=19&coverage_items_0_id=134081&coverage_items_1_coverage_amount=16&coverage_items_1_coverage_code=O&coverage_items_1_deductible_amount=17&coverage_items_1_id=134080&coverage_items_2_coverage_amount=14&coverage_items_2_coverage_code=O&coverage_items_2_deductible_amount=15&coverage_items_2_id=134079&coverage_items_3_coverage_amount=12&coverage_items_3_coverage_code=G&coverage_items_3_deductible_amount=13&coverage_items_3_id=134078&coverage_items_4_coverage_amount=10&coverage_items_4_coverage_code=F&coverage_items_4_deductible_amount=11&coverage_items_4_id=134077&coverage_items_5_coverage_amount=8&coverage_items_5_coverage_code=E&coverage_items_5_deductible_amount=9&coverage_items_5_id=134076&coverage_items_6_coverage_amount=6&coverage_items_6_coverage_code=D&coverage_items_6_deductible_amount=7&coverage_items_6_id=134075&coverage_items_7_coverage_amount=4&coverage_items_7_coverage_code=C&coverage_items_7_deductible_amount=5&coverage_items_7_id=134074&coverage_items_8_coverage_amount=2&coverage_items_8_coverage_code=B&coverage_items_8_deductible_amount=3&coverage_items_8_id=134073&coverage_items_9_coverage_amount=165000&coverage_items_9_coverage_code=A&coverage_items_9_deductible_amount=500&coverage_items_9_id=134072&created=2010-09-29&effective=2010-01-20&error_message=null&expired=2011-01-20&id=15318&insurance_company_address_1=988+WALNUT+STREET%2C+BOX+123&insurance_company_address_2=address+two&insurance_company_city=XYA&insurance_company_id=15286&insurance_company_naic_code=00000&insurance_company_name=XYZ&insurance_company_phone_number=5159924121&insurance_company_state=IA&insurance_company_zip_code=500630624&insured_address_1=2885+130TH+STREET&insured_address_2=second+address&insured_city=YALE&insured_country=USA&insured_first_name=CLEMENTINE&insured_id=15288&insured_last_name=XXX&insured_name_2=asdf&insured_state=IA&insured_zip_code=502770000&loaded=2014-01-07T01%3A02%3A27.302&mortgagee_address_1=1224+1ST+STREET&mortgagee_address_2=P.O.+BOX+8&mortgagee_city=PERRY&mortgagee_country=GBR&mortgagee_id=15288&mortgagee_loan_number=XXX&mortgagee_mortgagee_type=1ST&mortgagee_name_1=WELLS+FARGO+BANK&mortgagee_name_2=FIRST+AMERICAN&mortgagee_state=IA&mortgagee_zip_code=502200000&policy_id=00183&policy_type_code=19&property_address=Acres%3A+++++Qtr%3A+SE+Sec%3A+18+Twp%3A+81++Rng%3A+30&property_city=GUTHRIE&property_country=USR&property_description=Dwelling&property_id=15280&property_state=IA&property_zip_code=00000&reason=AM&received=null&send=true&status=null&transaction_id=201009290000002', encoded_payload)

        decoded_key = base64.urlsafe_b64decode(self.private_key.encode('utf-8'))
        signature = hmac.new(decoded_key, url_to_sign + encoded_payload, hashlib.sha256)
        result = base64.urlsafe_b64encode(signature.digest())
        self.assertEqual('3jIIkkTf3vue3rNt0QT6bUGx8wp1AfhOGlgVvVIG3I8=', result)

        actual = self.signer.create_signature(base_url, payload)
        self.assertEqual(result, actual)


if __name__ == '__main__':
    main()
