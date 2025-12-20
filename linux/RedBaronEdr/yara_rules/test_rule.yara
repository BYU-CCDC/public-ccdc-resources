rule TestYaraRule
{
    strings:
        $test_string = "YARA test string"
    condition:
        $test_string
}