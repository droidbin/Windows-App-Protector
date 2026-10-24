# Windows App Protector

WinUI 3 기반 Windows 앱 실행 차단 도구입니다. 보호 목록에 등록한 `.exe` 파일을 Windows IFEO(Image File Execution Options) 규칙 또는 창 감시 방식으로 차단합니다.

현재 작업 버전: `1.2.0-beta.5` (안정판 배포 아님)

## 배포 파일

최종 배포 파일은 아래 하나입니다.

```text
dist\installer\Setup.exe
```

버전별 보존용 빌드 산출물은 `dist\releases\<버전>`에 별도로 저장됩니다.

사용자는 `Setup.exe`만 실행하면 됩니다. 설치 프로그램은 관리자 권한을 요청한 뒤 다음 작업을 자동으로 처리합니다.

- 실행 중인 기존 Windows App Protector 프로세스 종료
- 이전 버전에서 남긴 관리형 IFEO 차단 규칙 정리
- 기존 버전 및 `.old` 설치 폴더 제거, 이전 바로가기·시작 작업·제거 등록 정리
- PIN·사용자 설정·보호 앱 목록 보존
- 새 설치 파일의 압축과 필수 파일을 검증한 뒤, 기존 버전을 제거하고 `C:\Program Files\Windows App Protector <버전>`에 설치
- 기존 버전 제거 실패 시 새 설치 중단
- 선택 시 바탕화면 및 시작 메뉴 바로가기 생성
- Windows 앱 제거 목록 등록
- 설치 완료 후 앱 실행

## 빌드

개발 PC에서 아래 명령만 실행하면 WinUI 앱과 설치 파일이 함께 생성됩니다.

```powershell
.\build_setup.bat
```

빌드 결과:

```text
dist\installer\Setup.exe
```

## 업데이트 배포

자동 업데이트는 GitHub Releases의 최신 릴리즈를 기준으로 동작합니다.

- 안정판 릴리즈 태그는 `V1.2.0`처럼 앱 버전과 맞춥니다.
- 베타 빌드는 `1.2.0-beta.N`으로 표기하고 GitHub의 사전 릴리즈(Pre-release)로 공개하며, 안정판의 Latest 표시는 유지합니다.
- 새 버전 설치 시 기존 설치 폴더를 제거합니다. GitHub의 기존 릴리즈·태그·자산은 보존하며 새 태그로 배포합니다.
- 이 앱은 사용자의 릴리즈 요청 시 별도 승인 없이 커밋·푸시·GitHub 릴리즈와 배포 자산 검증까지 진행합니다.
- 안정판을 게시하기 전 Windows 빌드, 자동 업데이트 해시 검증, 설치/업그레이드 및 재부팅 동작을 확인합니다.
- 릴리즈 자산에는 `Setup.exe`와 `WindowsAppProtector.zip`을 첨부합니다. 자동 업데이트는 GitHub 릴리스 자산의 SHA-256 digest를 확인합니다.
- `Setup.exe`가 없으면 `WindowsAppProtector.zip` 안의 `Setup.exe`를 찾아 설치합니다.
- private 저장소를 사용할 경우 `WINDOWS_APP_PROTECTOR_GITHUB_TOKEN` 환경 변수 또는 `%PROGRAMDATA%\Windows App Protector\github-token.txt`에 GitHub 토큰을 넣어야 합니다.

## 베타 및 안정판 운영

- 작업은 현재 안정판에서 분기한 `codex/` 또는 `beta/` 작업 브랜치에서 진행합니다.
- 변경 사항은 로컬 또는 클라우드 Windows 빌드에서 검증하고, 베타 버전 식별자와 검증 결과를 기록합니다.
- 검증 전에는 안정판 태그, GitHub Release, 설치 파일을 게시하지 않습니다.
- 안정화 시 기본 브랜치에 병합한 커밋에서 버전과 설치 파일을 빌드하고, 산출물 SHA-256 및 설치/업그레이드 결과를 확인한 다음 GitHub Release를 게시합니다.
- GitHub Actions의 Windows 빌드 검증은 자동 릴리스 게시를 수행하지 않습니다.

## 주요 기능

- 여러 `.exe` 앱 보호 목록 관리
- 선택 앱 잠금/해제
- 목록 잠금/해제
- 앱 최초 실행 및 백그라운드 복귀 시 PIN 인증
- 일정 시간 유휴 상태 시 보호 목록 자동 잠금
- Windows 시작 시 자동 실행 ON/OFF
- GitHub Releases 기반 자동 업데이트
- 전역 단축키 등록 및 설정
- 중복 단축키 감지
- 잠금 시 실행 중인 Win32 보호 앱에 정상 종료를 요청하는 선택 옵션 (기본 꺼짐, 5초 대기, 강제 종료 없음)
- X 버튼 클릭 시 백그라운드 숨김 아이콘으로 전환
- 프로그램 종료 메뉴 선택 시 백그라운드 프로세스까지 종료
- Windows Service 기반 보호 규칙 감시 및 복구
- ProgramData 설정은 관리자와 SYSTEM만 수정할 수 있으며, 서비스는 이 신뢰 경로만 읽음
- PIN 해시는 PBKDF2-SHA256 및 고정 시간 비교로 확인
- 앱 실행 파일, 창/작업 표시줄, 시스템 트레이 및 설치 프로그램에 방패형 아이콘 적용
- 설정 저장 위치: `%APPDATA%\WindowsAppProtector.WinUI`
- 서비스 감시 설정 위치: `%PROGRAMDATA%\Windows App Protector\config.json`
- Windows App SDK 2.0.1 기반 WinUI 3 앱
- 설치형 `Setup.exe` 패키지

## 기본 단축키

- `Ctrl+Alt+W`: 창 보이기/숨기기
- `Ctrl+Shift+L`: 목록 잠금
- `Ctrl+Shift+U`: 목록 해제

## 차단 방식

보호 기능은 아래 레지스트리에 관리형 규칙을 등록해서 동작합니다.

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
```

Chrome, Edge, Samsung Internet 같은 브라우저는 확장 프로그램과 렌더러 프로세스도 같은 실행 파일을 사용하므로 IFEO 대신 창 감시 방식으로 잠급니다. 이 방식은 브라우저 확장 프로세스를 끊지 않으면서 잠금 상태의 브라우저 창을 숨깁니다.

차단된 앱을 새로 실행하면 대상 앱을 강제 종료하지 않고 실행만 막습니다. 기본 설정에서는 이미 실행 중인 앱을 유지합니다. 설정에서 잠금 시 앱 종료를 켜면 Win32 보호 앱에 정상 종료를 요청하고 5초 대기합니다. 패키지 앱은 종료 대상에서 제외되며, 종료를 거부하는 앱은 강제 종료하지 않습니다. 저장되지 않은 작업은 손실될 수 있습니다.

Windows 시작 시 자동 실행은 관리자 권한 앱이 로그인 후 안정적으로 실행되도록 `Windows App Protector` 예약 작업으로 등록합니다. 이전 버전의 HKCU Run 등록은 새 설정 저장 시 자동으로 정리됩니다.

## 보호 서비스

설치 시 `WindowsAppProtectorService`가 자동 시작 서비스로 등록됩니다.

서비스는 `%PROGRAMDATA%\Windows App Protector\config.json`을 기준으로 보호 상태를 감시하고, 사용자가 UI 프로세스를 작업 관리자에서 강제 종료해도 관리형 IFEO 차단 규칙을 주기적으로 복구합니다.

서비스는 사용자의 데스크톱 UI를 직접 다시 띄우지는 않습니다. UI가 종료되어도 차단 규칙은 유지/복구되며, 설정 변경이나 단축키 기능이 필요하면 사용자가 앱을 다시 실행하면 됩니다.

## 제거

Windows 설정의 앱 제거 목록에서 `Windows App Protector`를 제거하거나 설치 폴더의 `uninstall.bat`을 실행하면 됩니다.

제거 시 Windows Service, 시작 예약 작업, 관리형 IFEO 규칙, 서비스 설정, 바로가기가 함께 정리됩니다.
