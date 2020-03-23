#!/bin/bash
#
# script to control IDS server
# Version: 2.1
#
# History:
# 0.0.1 2010 March - Created
# 0.1.0 2010 July - Fix for new release
# 0.1.1 2010 November - add reload option
# 2.0 2013 September - make action in functions and add restart option
# 2.1 2014 February - check in start_action is other files is running
# 3.0 2014 December - prepare for repository (separate cfg/)
#
# Copyright by BROWARSKI
#
if [ -z $LOGNAME ]; then
	LOGNAME=$USER
fi

BASEDIR=/home/$LOGNAME/get/
BIN=$BASEDIR/netbone/bin
CFG=$BASEDIR/netbone/cfg
echo using binary $BIN 
PID_FILES=$BASEDIR/pid/files.pid
PID_SENDD=$BASEDIR/pid/sendd.pid
echo pid files: files $PID_FILES sendd $PID_SENDD
PID=0
PID0=0
SPID=0

cd $BIN

get_pid_files () {
	if [ -f $PID_FILES ]; then
		PID=`cat $PID_FILES`;
	fi
}
get_pid_sendd () {
	if [ -f $PID_SENDD ]; then
                SPID=`cat $PID_SENDD`;
        fi
}
action_stop () {
	if [ $PID -gt $PID0 ]; then
                echo stop: files $PID
        	kill -INT $PID
	fi

	if [ $SPID -gt $PID0 ]; then
        	echo stop: sendd $SPID
                #
                # safe close
                #
               kill -INT $SPID;
        fi
}

action_kill () {
        if [ $PID -gt $PID0 ]; then
        	echo kill: files $PID
               	kill -9 $PID
        fi

        if [ $SPID -gt $PID0 ]; then
                echo kill: sendd $SPID
               	kill -9 $SPID;
        fi
}

action_start () {
	echo "FILES starting"
	check=`ps -ef | grep files | grep $BIN | wc -l`
        if [ "$check" == "0" ]; then
		$BIN/files $CFG/server.lst
        else
        	echo "other files process is running, please check: $check";
        fi

}


case $1 in
	start)
		action_start
		get_pid_files
	;;
	start-fc)
		./filefc
	;;
	restart)
		get_pid_files
                get_pid_sendd
                action_stop
		sleep 15;
		action_kill
		sleep 5;
		action_start
		get_pid_files
	;;
		
	stop)
		get_pid_files
		get_pid_sendd
		action_stop
	;;
	dump)
		get_pid_files
                #
                # is this a number
                #
                if [ $PID -gt $PID0 ]
		then
			kill -USR1 $PID;
		fi 
	;;
	kill)
		get_pid_files
                get_pid_sendd
		action_kill
	;;
	reload)
		get_pid_files
		if [ $PID -gt $PID0 ]
		then
			if kill -1 $PID
			then 
				echo IDS reloaded;
			fi
		else
			echo "Np $PID_FILE found"
		fi
	;;
	log)
		get_pid_files
		/usr/bin/tail -n 50 -f $BASEDIR/log_perm/log-$PID.*
	;;
	status)
		get_pid_files

		if [ $PID -gt $PID0 ];  then
			if kill -0 $PID
			then
				echo IDS exists: $PID;
			else
				/bin/rm $PID_FILES;
			fi
		else 
			echo "No $PID_FILES found";
		fi

		get_pid_sendd

		if [ $SPID -gt $PID0 ]; then
                        if kill -0 $SPID
                        then
                                echo SENDD exists: $SPID;
                        else
                                /bin/rm $PID_SENDD;
                        fi
                else
                        echo "No $PID_SEND found"
                fi
	;;
	*)
		echo "Unknown system command, allowed: stop, start, restart, start-fc, status, dump, kill, reload";
	;;
esac
