REM @echo off
set version=%1
if %version% == "" goto error
if exist Z:\tmp\uv-x86_64-pc-windows-msvc\uv.exe set "PATH=Z:\tmp\uv-x86_64-pc-windows-msvc;%PATH%"

set UV_PROJECT_ENVIRONMENT=.venvw
echo Building version %version% for windows
uv sync --extra packaging
if errorlevel 1 goto error

set PYINST_FLAGS=--distpath standalone-win --specpath build-win --workpath build-win
if errorlevel 1 goto error
uv run pyinstaller %PYINST_FLAGS% --name gangway-login --onefile src/oidc_form_login/gangway.py
if errorlevel 1 goto error
uv run pyinstaller %PYINST_FLAGS% --name oidc-form-login --onefile src/oidc_form_login/login.py
if errorlevel 1 goto error

mkdir dist-%version%

copy standalone-win\oidc-form-login.exe dist-%version%\oidc-form-login-%version%-windows-amd64.exe
if errorlevel 1 goto error
copy standalone-win\gangway-login.exe dist-%version%\gangway-login-%version%-windows-amd64.exe
if errorlevel 1 goto error

echo Build succeeded
exit /B

:error
echo Build failed
exit /B 1
