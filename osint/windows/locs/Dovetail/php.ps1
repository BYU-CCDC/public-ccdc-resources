$php = Get-ChildItem -Path "C:\" -Filter "php.exe" -Recurse -ErrorAction SilentlyContinue |
    ForEach-Object { & $_.FullName --ini | Out-String }

$ConfigFiles = @()
foreach ($OutputLine in ($php -split "`r`n")) {
    if ($OutputLine -match 'Loaded') {
        $ConfigFiles += ($OutputLine -split "\s{9}")[1]
    }
}

$ConfigString_DisableFuncs = "disable_functions=exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"
$ConfigString_FileUploads        = "file_uploads=off"
$ConfigString_TrackErrors        = "track_errors = off"
$ConfigString_HtmlErrors         = "html_errors = off"
$ConfigString_MaxExecutionTime   = "max_execution_time = 3"
$ConfigString_DisplayErrors      = "display_errors = off"
$ConfigString_ShortOpenTag       = "short_open_tag = off"
$ConfigString_SessionCookieHTTPO = "session.cookie_httponly = 1"
$ConfigString_SessionUseCookies  = "session.use_only_cookies = 1"
$ConfigString_SessionCookieSecure= "session.cookie_secure = 1"
$ConfigString_ExposePhp          = "expose_php = off"
$ConfigString_MagicQuotesGpc     = "magic_quotes_gpc = off"
$ConfigString_AllowUrlFopen      = "allow_url_fopen = off"
$ConfigString_AllowUrlInclude    = "allow_url_include = off"
$ConfigString_RegisterGlobals    = "register_globals = off"

$ConfigStrings = @(
    $ConfigString_DisableFuncs,
    $ConfigString_FileUploads,
    $ConfigString_TrackErrors,
    $ConfigString_HtmlErrors,
    $ConfigString_MaxExecutionTime,
    $ConfigString_DisplayErrors,
    $ConfigString_ShortOpenTag,
    $ConfigString_SessionCookieHTTPO,
    $ConfigString_SessionUseCookies,
    $ConfigString_SessionCookieSecure,
    $ConfigString_ExposePhp,
    $ConfigString_MagicQuotesGpc,
    $ConfigString_AllowUrlFopen,
    $ConfigString_AllowUrlInclude,
    $ConfigString_RegisterGlobals
)


foreach ($ConfigFile in $ConfigFiles) {
    foreach ($Config in $ConfigStrings) {
        Add-Content -Path $ConfigFile -Value $Config
    }
    Write-Output "$Env:ComputerName [INFO] Configuration updated in $ConfigFile"
}

iisreset

if ($Error[0]) {
    Write-Output "`n#########################"
    Write-Output "#        ERRORS         #"
    Write-Output "#########################`n"
    foreach ($err in $Error) {
        Write-Output $err
    }
}