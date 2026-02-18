@echo off
REM Render ground truth architecture diagram to PNG

echo ================================================================================
echo ARCHITECTURE DIAGRAM RENDERER
echo ================================================================================
echo.

REM Try to find dot.exe in common locations
set DOT_PATH=

REM Check if in PATH
where dot >nul 2>nul
if %ERRORLEVEL% == 0 (
    set DOT_PATH=dot
    goto :render
)

REM Check common Graphviz install locations
if exist "C:\Program Files\Graphviz\bin\dot.exe" (
    set DOT_PATH="C:\Program Files\Graphviz\bin\dot.exe"
    goto :render
)

if exist "C:\Program Files (x86)\Graphviz\bin\dot.exe" (
    set DOT_PATH="C:\Program Files (x86)\Graphviz\bin\dot.exe"
    goto :render
)

if exist "%LOCALAPPDATA%\Programs\Graphviz\bin\dot.exe" (
    set DOT_PATH="%LOCALAPPDATA%\Programs\Graphviz\bin\dot.exe"
    goto :render
)

:not_found
echo [ERROR] Graphviz not found!
echo.
echo Please install Graphviz:
echo   1. Download from: https://graphviz.org/download/
echo   2. Install (use default location)
echo   3. Run this script again
echo.
echo OR render online:
echo   1. Go to: https://dreampuf.github.io/GraphvizOnline/
echo   2. Copy/paste contents of tm/ground_truth_architecture.dot
echo   3. Download PNG
echo.
pause
exit /b 1

:render
echo Found Graphviz: %DOT_PATH%
echo.

REM Render PNG
echo Rendering tm/ground_truth_architecture.png...
%DOT_PATH% -Tpng tm\ground_truth_architecture.dot -o tm\ground_truth_architecture.png

if %ERRORLEVEL% == 0 (
    echo [SUCCESS] Diagram rendered successfully!
    echo.
    echo Output: tm\ground_truth_architecture.png
    echo.
    echo Opening diagram...
    start tm\ground_truth_architecture.png
) else (
    echo [ERROR] Rendering failed!
    echo.
    echo Try manually:
    echo   %DOT_PATH% -Tpng tm\ground_truth_architecture.dot -o tm\ground_truth_architecture.png
)

echo.
pause
