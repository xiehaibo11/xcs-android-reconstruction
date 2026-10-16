# Shared host-test JDK discovery. Source this file from a suite after locating it.
if [ -n "${JAVA_HOME:-}" ]; then
    XCS_JAVAC="$JAVA_HOME/bin/javac"
    XCS_JAVA="$JAVA_HOME/bin/java"
elif command -v javac >/dev/null 2>&1 && javac -version >/dev/null 2>&1; then
    XCS_JAVAC=$(command -v javac)
    XCS_JAVA=$(command -v java)
elif [ -x /usr/libexec/java_home ] && xcs_discovered_java_home=$(/usr/libexec/java_home 2>/dev/null); then
    XCS_JAVAC="$xcs_discovered_java_home/bin/javac"
    XCS_JAVA="$xcs_discovered_java_home/bin/java"
else
    printf '%s\n' 'Set JAVA_HOME to a JDK 17 or newer, or put java/javac on PATH.' >&2
    exit 1
fi
if [ ! -x "$XCS_JAVAC" ] || [ ! -x "$XCS_JAVA" ]; then
    printf '%s\n' 'JAVA_HOME does not provide executable java and javac.' >&2
    exit 1
fi
