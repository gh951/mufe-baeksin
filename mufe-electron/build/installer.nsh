; MUFE 백신 — NSIS 설치 박음
; 한 번 클릭 박는 자리

!macro customHeader
  RequestExecutionLevel user
!macroend

!macro preInit
  SetRegView 64
  WriteRegExpandStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "InstallLocation" "$INSTDIR"
  WriteRegExpandStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "InstallLocation" "$INSTDIR"
!macroend

!macro customInstall
  ; 빠른 박음
  DetailPrint "MUFE 백신 박는 중..."
  
  ; 방화벽 박음 (Windows Defender 자리)
  ExecWait 'netsh advfirewall firewall add rule name="MUFE Baeksin" dir=in action=allow program="$INSTDIR\MUFE 백신.exe" enable=yes' $0
!macroend

!macro customUnInstall
  ; 방화벽 박힘 X
  ExecWait 'netsh advfirewall firewall delete rule name="MUFE Baeksin"' $0
!macroend
