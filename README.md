# App PIN Guard

WinUI 3 기반 Windows 앱 실행 차단 도구입니다. 보호 목록에 등록한 `.exe` 파일을 Windows IFEO(Image File Execution Options) 규칙 또는 창 감시 방식으로 차단합니다.

공개 안정판은 기존 이름인 Windows App Protector `1.3.0`입니다. 2.0 개발 빌드부터 App PIN Guard 이름을 사용합니다.

## 배포 파일

최종 배포 파일은 아래 하나입니다.

```text
dist\installer\Setup.exe
```

버전별 보존용 빌드 산출물은 `dist\releases\<버전>`에 별도로 저장됩니다.

사용자는 `Setup.exe`만 실행하면 됩니다. 설치 프로그램은 관리자 권한을 요청한 뒤 다음 작업을 자동으로 처리합니다.

- 실행 중인 기존 보호 프로그램 프로세스 종료
- 이전 버전에서 남긴 관리형 IFEO 차단 규칙 정리
- 기존 버전 및 `.old` 설치 폴더 제거, 이전 바로가기·시작 작업·제거 등록 정리
- PIN·사용자 설정·보호 앱 목록 보존
- 새 설치 파일의 압축·필수 파일·앱 실행을 검증한 뒤, 기존 버전을 제거하고 `C:\Program Files\Windows App Protector <버전>`에 설치
- .NET 및 Windows App SDK 런타임을 앱 폴더에 포함하므로 별도 런타임 설치나 설치 중 인터넷 연결 불필요
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

- 버전 규칙: 메이저 업데이트는 1 단위(`2.0.0`), 마이너 업데이트는 0.1 단위(`1.3.0`), 버그 수정은 0.001 단위로 세 번째 자리를 올립니다(`1.3.0` → `1.3.1`, … `1.3.11`).
- 안정판 릴리즈 태그는 `V1.3.0`처럼 앱 버전과 맞춥니다.
- 베타 빌드는 `1.3.0-beta.N`으로 표기하고 GitHub의 사전 릴리즈(Pre-release)로 공개하며, 안정판의 Latest 표시는 유지합니다.
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
- 2.0 설정·PIN 해시 저장 위치: `%PROGRAMDATA%\Windows App Protector\config.json`
- 처음 시작할 때 기존 정책을 한 번 이전합니다. 공유 폴더에 등록된 보호 정책을 우선하며, 이전이 끝나면 사용자 프로필의 1.x 설정과 PIN 백업은 2.0에서 사용하지 않습니다. 1.x 복귀용 기존 파일은 그대로 남습니다.
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

Chrome, Edge, Samsung Internet 같은 브라우저와 스토어/MSIX 앱은 세션 에이전트가 창을 감시합니다. 브라우저는 등록한 실행 파일의 전체 경로, 스토어/MSIX 앱은 패키지 패밀리 이름으로 판정합니다. 잠금 중에는 창을 숨기며 프로세스 자체는 그대로 둡니다.

차단된 앱을 새로 실행하면 대상 앱을 강제 종료하지 않고 실행만 막습니다. 기본 설정에서는 이미 실행 중인 앱을 유지합니다. 설정에서 잠금 시 앱 종료를 켜면 Win32 보호 앱에 정상 종료를 요청하고 5초 대기합니다. 패키지 앱은 종료 대상에서 제외되며, 종료를 거부하는 앱은 강제 종료하지 않습니다. 저장되지 않은 작업은 손실될 수 있습니다.

Windows 시작 시 자동 실행은 관리자 권한 앱이 로그인 후 안정적으로 실행되도록 `Windows App Protector` 예약 작업으로 등록합니다. 이전 버전의 HKCU Run 등록은 새 설정 저장 시 자동으로 정리됩니다.

## 보호 서비스

설치 시 `WindowsAppProtectorService`가 자동 시작 서비스로 등록됩니다.

서비스는 `%PROGRAMDATA%\Windows App Protector\config.json`을 기준으로 보호 상태를 감시하고, 사용자가 UI 프로세스를 작업 관리자에서 강제 종료해도 관리형 IFEO 차단 규칙을 주기적으로 복구합니다.

서비스는 로그인한 세션에 사용자 권한으로 창 감시 에이전트를 실행하고, 에이전트가 종료되면 다시 시작합니다. 에이전트에는 창 감시에 필요한 앱 식별값만 전달합니다. 관리 화면을 닫아도 창 감시는 계속되며, 설정 변경과 단축키는 관리 프로그램에서 처리합니다.

## 제거

Windows 설정의 앱 제거 목록에서 `App PIN Guard`를 제거하거나 설치 폴더의 `uninstall.bat`을 실행하면 됩니다. 1.x에서는 기존 이름인 `Windows App Protector`로 표시됩니다.

제거 시 Windows Service, 시작 예약 작업, 관리형 IFEO 규칙, 서비스 설정, 바로가기가 함께 정리됩니다.
