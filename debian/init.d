#!/bin/bash
#
# Araneum start/stop script for Linux
#
### BEGIN INIT INFO
# Provides:          araneum httpd httpd-cgi
# Required-Start:    $syslog $network
# Required-Stop:     $syslog $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Araneum HTTP Server
# Description:       Araneum is a high performance, flexible and easy to use and configure Web Server.
### END INIT INFO

PATH="/bin:/usr/bin:/sbin:/usr/sbin"
ARANEUM="/usr/sbin/araneum"
WIGWAM="/usr/sbin/wigwam"
PIDFILE="/var/run/araneum.pid"

NORMAL="\033[0m"
RED="\033[00;31m"
YELLOW="\033[00;33m"
GREEN="\033[00;32m"

if [ ! -f ${ARANEUM} ]; then
	echo -e "${ARANEUM} not found."
	exit 1;
fi

function start_araneum {
	if [ -f ${PIDFILE} ]; then
		echo -e "${YELLOW}Araneum is already running${NORMAL}"
	else
		${WIGWAM} -q
		result=$?

		if [ "${result}" = "0" ]; then
			echo -n "Starting webserver: "
			${ARANEUM}
			result=$?
			if [ "${result}" = "0" ]; then
				echo -e "${GREEN}Araneum${NORMAL}"
			else
				echo -e "${RED}error!${NORMAL}"
			fi
		else
			echo -e "${RED}Araneum has NOT been started!${NORMAL}"
		fi
	fi
}

function stop_araneum {
	if [ -f ${PIDFILE} ]; then
		echo -en "Stopping webserver: ${GREEN}"
		PID=`cat ${PIDFILE}`
		kill -15 ${PID}

		WAIT="10"
		while [ -d /proc/${PID} ]; do
			if [ "${WAIT}" != "0" ]; then
				sleep 1
				let WAIT=${WAIT}-1
			else
				kill -9 ${PID}
				echo -en "${RED}warning, possible incorrect shutdown of "
				break
			fi
		done

		rm -f ${PIDFILE}
		echo -e "Araneum${NORMAL}"
	else
		echo -e "${YELLOW}Araneum is not running${NORMAL}"
	fi
}

function config_check {
	echo -e "${YELLOW}Configuration check via Wigwam...${NORMAL}"
	${WIGWAM}
	echo
	echo -e "${YELLOW}Configuration check via Araneum...${NORMAL}"
	${HIAWATHA} -k
}

function show_status {
	if [ -f $PIDFILE ] && ps `cat $PIDFILE` >/dev/null 2>&1; then
		echo -e "${GREEN}Araneum is running${NORMAL}"
	else
		echo -e "${RED}Araneum is not running${NORMAL}"
	fi
}

case "$1" in
	start)
		start_araneum
		;;
	stop)
		stop_araneum
		;;
	restart)
		stop_araneum
		start_araneum
		;;
	check)
		config_check
		;;
	status)
		show_status
		;;
	*)
		echo "Usage: $0 {start|stop|restart|check|status}"
		exit 1
		;;
esac

exit 0
