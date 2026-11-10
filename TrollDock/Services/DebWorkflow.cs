using System;

namespace TrollDock.Services;

/// <summary>Builds POSIX sh scripts for the package tools already installed by the jailbreak.</summary>
public static class DebWorkflow
{
    public static string GetPreflightScript(string remoteDebPath)
    {
        ValidatePath(remoteDebPath);
        return CommonScript + "\nDEB=" + Quote(remoteDebPath) + "\n" + PreflightScript;
    }

    public static string GetInstallScript(string remoteDebPath)
    {
        // Repeat validation in the installation command rather than trusting an earlier preflight.
        return GetPreflightScript(remoteDebPath) + "\n" + """
            printf '%s\n' 'TROLLDOCK_STAGE:installing'
            if "$APT" --assume-yes --no-remove \
                -o Dpkg::Use-Pty=0 \
                -o Dpkg::Options::=--force-confold \
                install "$DEB" </dev/null; then
                INSTALLED_STATUS=$("$DPKG_QUERY" -W -f '${Status}' "$PACKAGE") || fail VERIFY_FAILED 'APT завершился, но пакет не найден в базе dpkg.'
                INSTALLED_VERSION=$("$DPKG_QUERY" -W -f '${Version}' "$PACKAGE") || fail VERIFY_FAILED 'Не удалось проверить установленную версию пакета.'
                [ "$INSTALLED_STATUS" = 'install ok installed' ] || fail VERIFY_FAILED 'Пакет установлен не полностью. Проверьте состояние пакета в Sileo или Zebra.'
                if [ "$INSTALLED_VERSION" != "$VERSION" ]; then
                    printf 'TROLLDOCK_ERROR:VERSION_MISMATCH|После установки dpkg сообщает версию %s вместо выбранной %s.\n' "$INSTALLED_VERSION" "$VERSION" >&2
                    exit 1
                fi
                printf '%s\n' 'TROLLDOCK_RESULT:installed'
            else
                result=$?
                printf 'TROLLDOCK_ERROR:APT_FAILED|APT завершился с кодом %s. Подробности указаны выше; проверьте зависимости и доступность репозиториев в Sileo или Zebra.\n' "$result" >&2
                exit "$result"
            fi
            """ + "\n";
    }

    public static string GetRespringScript() => CommonScript + "\n" + """
        require_root
        for tool in /var/jb/usr/bin/sbreload /var/jb/usr/sbin/sbreload /usr/bin/sbreload /usr/sbin/sbreload; do
            if [ -x "$tool" ]; then
                printf '%s\n' 'TROLLDOCK_STAGE:respring'
                exec "$tool"
            fi
        done
        tool=$(command -v sbreload 2>/dev/null || :)
        case "$tool" in
            /*) if [ -x "$tool" ]; then
                    printf '%s\n' 'TROLLDOCK_STAGE:respring'
                    exec "$tool"
                fi ;;
        esac
        fail RESPRING_UNAVAILABLE 'sbreload не найден. Выполните Respring через Sileo, Zebra или настройки твика.'
        """ + "\n";

    public static string Quote(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Contains('\0')) throw new ArgumentException("Shell arguments cannot contain NUL.", nameof(value));
        return "'" + value.Replace("'", "'\"'\"'") + "'";
    }

    private static void ValidatePath(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!value.StartsWith('/') || value.IndexOfAny(['\0', '\r', '\n']) >= 0)
            throw new ArgumentException("The remote DEB path must be absolute and contain no NUL or newline.", nameof(value));
    }

    private const string CommonScript = """
        set -eu
        PATH=/var/jb/usr/sbin:/var/jb/usr/bin:/var/jb/sbin:/var/jb/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}
        export PATH
        LC_ALL=C
        export LC_ALL
        export DEBIAN_FRONTEND=noninteractive
        fail() {
            printf 'TROLLDOCK_ERROR:%s|%s\n' "$1" "$2" >&2
            exit 1
        }
        require_root() {
            [ "$(id -u)" = 0 ] || fail ROOT_REQUIRED 'Для установки DEB нужен SSH-сеанс root. Текущий пользователь не имеет UID 0.'
        }
        find_tool() {
            for candidate in "/var/jb/usr/bin/$1" "/var/jb/usr/sbin/$1" "/usr/bin/$1" "/usr/sbin/$1" "/bin/$1"; do
                if [ -x "$candidate" ]; then
                    printf '%s\n' "$candidate"
                    return 0
                fi
            done
            candidate=$(command -v "$1" 2>/dev/null || :)
            case "$candidate" in
                /*) if [ -x "$candidate" ]; then
                        printf '%s\n' "$candidate"
                        return 0
                    fi ;;
            esac
            return 1
        }
        """;

    private const string PreflightScript = """
        require_root
        [ -f "$DEB" ] && [ -r "$DEB" ] || fail DEB_NOT_FOUND 'Загруженный DEB не найден или недоступен для чтения.'
        DPKG=$(find_tool dpkg) || fail DPKG_MISSING 'dpkg не найден. Проверьте, что jailbreak Dopamine активен и bootstrap установлен.'
        DPKG_DEB=$(find_tool dpkg-deb) || fail DPKG_DEB_MISSING 'dpkg-deb не найден. Восстановите пакет dpkg через Sileo или Zebra.'
        DPKG_QUERY=$(find_tool dpkg-query) || fail DPKG_QUERY_MISSING 'dpkg-query не найден. Восстановите пакет dpkg через Sileo или Zebra.'
        APT=$(find_tool apt-get) || fail APT_MISSING 'apt-get не найден. Установите APT через Sileo или Zebra; установка с игнорированием зависимостей не выполняется.'
        MODE=rootful
        case "$DPKG" in
            /var/jb/*)
                MODE=rootless
                case "$DPKG_DEB" in /var/jb/*) ;; *) fail MIXED_TOOLS 'Найдены инструменты dpkg от разных bootstrap. Проверьте окружение jailbreak.' ;; esac
                case "$DPKG_QUERY" in /var/jb/*) ;; *) fail MIXED_TOOLS 'Найдены инструменты dpkg от разных bootstrap. Проверьте окружение jailbreak.' ;; esac
                case "$APT" in /var/jb/*) ;; *) fail MIXED_TOOLS 'Найдены инструменты APT и dpkg от разных bootstrap. Проверьте окружение jailbreak.' ;; esac
                ;;
            *)
                for tool in "$DPKG_DEB" "$DPKG_QUERY" "$APT"; do
                    case "$tool" in /var/jb/*) fail MIXED_TOOLS 'Найдены инструменты от разных bootstrap. Проверьте окружение jailbreak.' ;; esac
                done
                ;;
        esac
        PACKAGE=$("$DPKG_DEB" -f "$DEB" Package) || fail INVALID_DEB 'Не удалось прочитать Package из DEB. Файл повреждён или имеет неподдерживаемый формат.'
        VERSION=$("$DPKG_DEB" -f "$DEB" Version) || fail INVALID_DEB 'Не удалось прочитать Version из DEB.'
        ARCH=$("$DPKG_DEB" -f "$DEB" Architecture) || fail INVALID_DEB 'Не удалось прочитать Architecture из DEB.'
        DEVICE_ARCH=$("$DPKG" --print-architecture) || fail DEVICE_ARCH_FAILED 'Не удалось определить архитектуру bootstrap.'
        case "$PACKAGE" in ''|*[!a-z0-9.+-]*|-*) fail INVALID_METADATA 'Некорректное имя пакета в DEB.' ;; esac
        case "$VERSION" in ''|*[!a-zA-Z0-9.+:~_-]*) fail INVALID_METADATA 'Некорректная версия пакета в DEB.' ;; esac
        case "$ARCH" in ''|*[!a-zA-Z0-9_-]*) fail INVALID_METADATA 'Некорректная архитектура пакета в DEB.' ;; esac
        case "$DEVICE_ARCH" in ''|*[!a-zA-Z0-9_-]*) fail DEVICE_ARCH_FAILED 'Некорректная архитектура bootstrap.' ;; esac
        printf 'TROLLDOCK_META:Package=%s\n' "$PACKAGE"
        printf 'TROLLDOCK_META:Version=%s\n' "$VERSION"
        printf 'TROLLDOCK_META:Architecture=%s\n' "$ARCH"
        printf 'TROLLDOCK_META:DeviceArchitecture=%s\n' "$DEVICE_ARCH"
        printf 'TROLLDOCK_META:JailbreakMode=%s\n' "$MODE"
        printf 'TROLLDOCK_META:AptPath=%s\n' "$APT"
        if [ "$MODE" = rootless ] && [ "$DEVICE_ARCH" != iphoneos-arm64 ]; then
            fail UNSUPPORTED_BOOTSTRAP 'Обнаружен нестандартный rootless bootstrap. Для Dopamine ожидается iphoneos-arm64.'
        fi
        if [ "$ARCH" != all ] && [ "$ARCH" != "$DEVICE_ARCH" ]; then
            printf 'TROLLDOCK_ERROR:ARCH_MISMATCH|Архитектура DEB (%s) не совпадает с архитектурой jailbreak (%s). Нужна совместимая версия пакета.\n' "$ARCH" "$DEVICE_ARCH" >&2
            exit 1
        fi
        printf '%s\n' 'TROLLDOCK_STAGE:checking_dependencies'
        if "$APT" --simulate --assume-yes --no-remove \
            -o Dpkg::Use-Pty=0 \
            -o Dpkg::Options::=--force-confold \
            install "$DEB" </dev/null; then
            :
        else
            result=$?
            printf 'TROLLDOCK_ERROR:APT_PREFLIGHT_FAILED|Проверка APT завершилась с кодом %s. Установка не начата; проверьте зависимости и конфликты в сообщениях выше.\n' "$result" >&2
            exit "$result"
        fi
        printf '%s\n' 'TROLLDOCK_PREFLIGHT:ready'
        """;
}
