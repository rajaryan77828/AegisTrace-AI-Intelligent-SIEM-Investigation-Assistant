"""AegisTrace AI — Sanitizer Test Suite"""
import unittest

from utils.sanitizer import (
    sanitize_html,
    strip_dangerous_tags,
    sanitize_for_display,
    sanitize_dict_values,
)


class TestSanitizeHTML(unittest.TestCase):
    def test_script_tag_escaped(self):
        result = sanitize_html('<script>alert("xss")</script>')
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_angle_brackets_escaped(self):
        result = sanitize_html("<b>bold</b>")
        self.assertNotIn("<b>", result)

    def test_quotes_escaped(self):
        result = sanitize_html('value="test"')
        self.assertIn("&quot;", result)

    def test_normal_text_unchanged(self):
        result = sanitize_html("Failed authentication attempt")
        self.assertEqual(result, "Failed authentication attempt")


class TestStripDangerousTags(unittest.TestCase):
    def test_script_removed(self):
        result = strip_dangerous_tags('<script>alert(1)</script>')
        self.assertNotIn("<script>", result)

    def test_iframe_removed(self):
        result = strip_dangerous_tags('<iframe src="evil.com"></iframe>')
        self.assertNotIn("<iframe", result)

    def test_event_handler_removed(self):
        result = strip_dangerous_tags('<img onerror="alert(1)" src="x">')
        self.assertNotIn("onerror", result)

    def test_javascript_uri_removed(self):
        result = strip_dangerous_tags('<a href="javascript:alert(1)">click</a>')
        self.assertNotIn("javascript:", result)


class TestSanitizeForDisplay(unittest.TestCase):
    def test_truncation(self):
        long_text = "A" * 1000
        result = sanitize_for_display(long_text, max_length=100)
        self.assertLessEqual(len(result), 110)  # Allow for escape expansion

    def test_html_escaped(self):
        result = sanitize_for_display("<script>bad</script>")
        self.assertNotIn("<script>", result)


class TestSanitizeDictValues(unittest.TestCase):
    def test_string_values_escaped(self):
        data = {"msg": "<script>xss</script>", "count": 5}
        result = sanitize_dict_values(data)
        self.assertNotIn("<script>", result["msg"])
        self.assertEqual(result["count"], 5)


if __name__ == "__main__":
    unittest.main()
