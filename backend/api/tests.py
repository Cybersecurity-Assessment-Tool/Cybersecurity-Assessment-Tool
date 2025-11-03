import unittest
from unittest.mock import patch, mock_open, MagicMock
import json
from api.services.ai_service import json_to_str, create_example, generate_report_content 

class TestReportGenerator(unittest.TestCase):

    # --- Test Cases for json_to_str ---
    @patch('builtins.open', new_callable=mock_open)
    def test_json_to_str_success(self, mock_file):
        """Tests successful compilation of multiple valid JSON files."""
        file1_content = '{"key1": "value1"}'
        file2_content = '{"key2": [1, 2, 3]}'
        
        mock_file.side_effect = (
            mock_open(read_data=file1_content).return_value,
            mock_open(read_data=file2_content).return_value
        )

        filepaths = ['data1.json', 'data2.json']
        result = json_to_str(filepaths)
        
        expected_output = (
            'data1.json:\n{\n  "key1": "value1"\n}\n--\n' +
            'data2.json:\n{\n  "key2": [\n    1,\n    2,\n    3\n  ]\n}\n--\n'
        )
        
        self.assertEqual(result, expected_output)
        self.assertEqual(mock_file.call_count, 2)

    @patch('builtins.open', side_effect=FileNotFoundError)
    def test_json_to_str_file_not_found(self, mock_file):
        """Tests handling of FileNotFoundError."""
        filepaths = ['missing.json']
        result = json_to_str(filepaths)
        self.assertEqual(result, '')
        mock_file.assert_called_once_with('missing.json', 'r', encoding='utf-8')

    @patch('builtins.open', new_callable=mock_open, read_data='invalid json')
    @patch('json.load', side_effect=json.JSONDecodeError('Expecting value', doc='invalid json', pos=1))
    def test_json_to_str_json_decode_error(self, mock_json_load, mock_file):
        """Tests handling of JSONDecodeError."""
        filepaths = ['bad_data.json']
        result = json_to_str(filepaths)
        self.assertEqual(result, '')
        mock_file.assert_called_once()
        mock_json_load.assert_called_once()
        
    # --- Test Cases for create_example ---
    def test_create_example_basic(self):
        """Tests the basic string concatenation for create_example."""
        prompt = "Create a security report."
        data = "file1.json:\n{...}\n--\n"
        result_str = "Report Content"
        
        expected = "Example:\nCreate a security report.\nfile1.json:\n{...}\n--\nReport Content"
        
        self.assertEqual(create_example(prompt, data, result_str), expected)
        
    def test_create_example_empty_inputs(self):
        """Tests create_example with empty strings."""
        self.assertEqual(create_example("", "", ""), "Example:\n\n")

    # --- Test Cases for generate_report_content ---
    # Haven't done these yet, as mocking the generation is a little difficult.