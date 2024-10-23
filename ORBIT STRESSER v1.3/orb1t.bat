@echo off
echo ---------------------------------------------------
echo          Terms of Service for [ORB1T]
echo ---------------------------------------------------
echo by agreeing to this/using this script you agree with the following:
echo.
echo the creator of orb1t prohibits, the use of orb1t for any type of unethical/illegal activities.
echo you have to take full responsibillity for any damage caused by orb1t.
echo the creator of orb1t is not liable for any damages or legal issues caused by orb1t.
echo this script/tool was created for only educational/testing purposes ONLY.
echo.
echo this script/tool was licensed under the MIT license, Any use or distribution of this script 
echo must include proper attribution to the original author. 
echo Claiming the source code as original work without acknowledgment is prohibited.
echo.
set /p agreement="Do you agree to the Terms of Service? (y/n): "
if /i "%agreement%"=="y" (
    echo loading up orb1t...
    python src\orb1t.py
) else (
    echo You did not agree to the Terms of Service. Exiting...
    exit /b
)
pause