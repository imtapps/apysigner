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
        expected_signature = 'KXFyxxwQ9B8_nM3TQeAmTYUa1_WhEFfm6YoMEX7tDCQ='
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
        self.assertEqual(unicode_payload['my_key_one'], None)

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
        orig = {'a': {'b': {'c': ['d']}}}
        new = self.signer._flatten(orig)
        self.assertEqual(new, {'a_b_c_0': 'd'})

    def test_flattens_dictionaries_nested_in_lists(self):
        orig = {'a': {'b': {'c': [{'d': 'e'}]}}}
        new = self.signer._flatten(orig)
        self.assertEqual(new, {'a_b_c_0_d': 'e'})

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


if __name__ == '__main__':
    main()
