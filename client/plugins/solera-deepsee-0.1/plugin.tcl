## Solera Networks Sguil Integration Plugin
## gbelknap@soleranetworks.com

# Copyright (c) 2010 Solera Networks, Inc

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# 
# Delete Wireshark and Transcript Options
$eventIDMenut delete 1 4

# Bolt on DeepSee Options to Event ID Menu
$eventIDMenut add command -label "Solera DeepSee" -command "Solera::Query sonar 5"
$eventIDMenut add command -label "Solera Artifact Search" -command "Solera::ArtifactSearch"

# Bolt on DeepSee Options to IP Query Menu
.ipQueryMenu add cascade -label "Solera DeepSee Query" -menu $ipQueryMenu.soleraMenu

menu $ipQueryMenu.soleraMenu -tearoff 0 -background $SELECTBACKGROUND -foreground $SELECTFOREGROUND \
-activeforeground $SELECTBACKGROUND -activebackground $SELECTFOREGROUND

foreach { currentMenu subcommand } { .ipQueryMenu.soleraMenu "solera" } {
    $currentMenu add cascade -label "Sonar / Index View" -menu $currentMenu.sonarMenu
    $currentMenu add cascade -label "Top Ports" -menu $currentMenu.portsMenu
    $currentMenu add cascade -label "Top Conversations" -menu $currentMenu.conversationsMenu
    $currentMenu add cascade -label "Packet Size Distribution" -menu $currentMenu.packet_sizeMenu
    $currentMenu add cascade -label "IP Discovery" -menu $currentMenu.ip_discoveryMenu
    $currentMenu add cascade -label "Bandwidth" -menu $currentMenu.bandwidthMenu

    menu $currentMenu.sonarMenu -tearoff 0 -background $SELECTBACKGROUND -foreground $SELECTFOREGROUND \
        -activeforeground $SELECTBACKGROUND -activebackground $SELECTFOREGROUND
    menu $currentMenu.portsMenu -tearoff 0 -background $SELECTBACKGROUND -foreground $SELECTFOREGROUND \
        -activeforeground $SELECTBACKGROUND -activebackground $SELECTFOREGROUND
    menu $currentMenu.conversationsMenu -tearoff 0 -background $SELECTBACKGROUND -foreground $SELECTFOREGROUND \
        -activeforeground $SELECTBACKGROUND -activebackground $SELECTFOREGROUND
	menu $currentMenu.packet_sizeMenu -tearoff 0 -background $SELECTBACKGROUND -foreground $SELECTFOREGROUND \
       	-activeforeground $SELECTBACKGROUND -activebackground $SELECTFOREGROUND
    menu $currentMenu.ip_discoveryMenu -tearoff 0 -background $SELECTBACKGROUND -foreground $SELECTFOREGROUND \
        -activeforeground $SELECTBACKGROUND -activebackground $SELECTFOREGROUND
    menu $currentMenu.bandwidthMenu -tearoff 0 -background $SELECTBACKGROUND -foreground $SELECTFOREGROUND \
        -activeforeground $SELECTBACKGROUND -activebackground $SELECTFOREGROUND

	$currentMenu.sonarMenu add command -label "SRC IP"			-command "Solera::Query sonar src 60"
	$currentMenu.sonarMenu add command -label "DST IP"			-command "Solera::Query sonar dst 60"
	$currentMenu.sonarMenu add command -label "Both"			-command "Solera::Query sonar src_and_dst 60"
	
	$currentMenu.portsMenu add command -label "SRC IP"			-command "Solera::Query ports src 60"
	$currentMenu.portsMenu add command -label "DST IP"			-command "Solera::Query ports dst 60"
	$currentMenu.portsMenu add command -label "Both"			-command "Solera::Query ports src_and_dst 60"
	
	$currentMenu.conversationsMenu add command -label "SRC IP"	-command "Solera::Query conversations src 60"
	$currentMenu.conversationsMenu add command -label "DST IP"	-command "Solera::Query conversations dst 60"
	$currentMenu.conversationsMenu add command -label "Both"	-command "Solera::Query conversations src_and_dst 60"
	
	$currentMenu.packet_sizeMenu add command -label "SRC IP"	-command "Solera::Query packet_size src 60"
	$currentMenu.packet_sizeMenu add command -label "DST IP"	-command "Solera::Query packet_size dst 60"
	$currentMenu.packet_sizeMenu add command -label "Both"		-command "Solera::Query packet_size src_and_dst 60"
	
	$currentMenu.ip_discoveryMenu add command -label "SRC IP"	-command "Solera::Query ip_discovery src 60"
	$currentMenu.ip_discoveryMenu add command -label "DST IP"	-command "Solera::Query ip_discovery dst 60"
	$currentMenu.ip_discoveryMenu add command -label "Both"		-command "Solera::Query ip_discovery src_and_dst 60"
	
	$currentMenu.bandwidthMenu add command -label "SRC IP"		-command "Solera::Query bandwidth src 60"
	$currentMenu.bandwidthMenu add command -label "DST IP"		-command "Solera::Query bandwidth dst 60"
	$currentMenu.bandwidthMenu add command -label "Both"		-command "Solera::Query bandwidth src_and_dst 60"
	
}

namespace eval Solera {
	
	set version "0.1"
	
	namespace export Query
	namespace export ArtifactSearch
	
	source "./plugins/solera-deepsee-${version}/plugin.conf"
		
	# Courtesy of CL, thanks man!
	proc launchBrowser url {
		global tcl_platform
		
		switch $tcl_platform(os) {
			Darwin {
		  		set command [list open $url]
			}
			HP-UX -
			Linux -
			SunOS {
		  		foreach executable {firefox mozilla netscape iexplorer opera lynx
									w3m links epiphany galeon konqueror mosaic amaya
			       					browsex elinks} {
		    	set executable [auto_execok $executable]
		    	if [string length $executable] {
					set command [list $executable $url &]
		      		break
		    		}
		  		}
			}
			{Windows 95} -
			{Windows NT} {
				# This sooo doesn't work on Win7
		  		set command "[auto_execok start] {} [list $url] &"
			}
	      }
		if [info exists command] {
		if [catch {exec $command &} err] {
		   ErrorMessage "error '$err' with '$command'"
		}
	      } else {
		 ErrorMessage \
		  "AWWWW SNAP! $tcl_platform(os), $tcl_platform(platform) is busticated for browsifying."
	      }
	}
	
	proc Query { report_type ips skew } {
	    global ACTIVE_EVENT SERVERHOST XSCRIPT_SERVER_PORT DEBUG CUR_SEL_PANE XSCRIPTDATARCVD
	    global socketWinName SESSION_STATE WIRESHARK_STORE_DIR WIRESHARK_PATH BROWSER_PATH
		global Solera::HOST Solera::USER Solera::PASS
	    if {!$ACTIVE_EVENT} {return}
	    set selectedIndex [$CUR_SEL_PANE(name) curselection]
	    set sidcidList [split [$CUR_SEL_PANE(name) getcells $selectedIndex,alertID] .]
	    set cnxID [lindex $sidcidList 1]
	    set sensorID [lindex $sidcidList 0]
	    set proto [$CUR_SEL_PANE(name) getcells $selectedIndex,ipproto]
	    set srcIP [$CUR_SEL_PANE(name) getcells $selectedIndex,srcip]
	    set srcPort [$CUR_SEL_PANE(name) getcells $selectedIndex,srcport]
	    set dstIP [$CUR_SEL_PANE(name) getcells $selectedIndex,dstip]
	    set dstPort [$CUR_SEL_PANE(name) getcells $selectedIndex,dstport]
	    if { $CUR_SEL_PANE(format) == "SSN" } {
	       set timestamp [$CUR_SEL_PANE(name) getcells $selectedIndex,starttime]
	    } else {
	       set timestamp [$CUR_SEL_PANE(name) getcells $selectedIndex,date]
	    } 
		# Set Time Skew (in Hours)
	     set startTime	[clock scan "$skew minutes" -base [clock scan $timestamp -gmt 1]]
	     set endTime	[clock scan "-$skew minutes" -base [clock scan $timestamp -gmt 1]]
		# Re-Format Time into Solera 'Timespan' Format
	    set startTime [clock format $startTime -format {%m.%d.%Y.%H.%M.%S} -gmt 1]
	    set endTime [clock format $endTime -format {%m.%d.%Y.%H.%M.%S} -gmt 1]

		set querySetup "https://$Solera::HOST/deepsee_reports?user=$Solera::USER&password=$Solera::PASS#pathString=%2Ftimespan%2F${startTime}.${endTime}"

		switch $ips {
			"src" {
				set queryIPs "%2Fipv4_address%2F${srcIP}"
			
			}
			"dst" {
				set queryIPs "%2Fipv4_address%2F${dstIP}"
			
			}
			"src_and_dst" {
				set queryIPs "%2Fipv4_address%2F${srcIP}_and_${dstIP}"
			}
		}
		switch $report_type {
			"sonar" {
				set queryType "%2F;reportIndex=0"
				}
			"ports" {
				set queryType "%2F;reportIndex=1"
			}
			"conversations" {
				set queryType "%2F;reportIndex=2"
			}
			"packet_size" {
				set queryType "%2F;reportIndex=3"
			}
			"ip_discovery" {
				set queryType "%2F;reportIndex=4"
			}
			"bandwidth" {
				set queryType "%2F;reportIndex=5"
			}
		}
		switch $proto {
			"6" {
				# TCP
				set queryProto "%2Ftcp_port%2F${srcPort}_and_${dstPort}%2F;reportIndex=0"
			}
			"17" {
				# UDP
				set queryProto "%2Fudp_port%2F${srcPort}_and_${dstPort}%2F;reportIndex=0"
			}
			"1" {
				# ICMP
				set queryProto "%2Fip_protocol%2Ficmp%2F;reportIndex=0"
			}
			default {
				# All Other Protocols
				set queryProto "%2F;reportIndex=0"
			}
		}
		exec $BROWSER_PATH $querySetup$queryIPs$queryProto$queryType &
	}

	proc ArtifactSearch { } {
	    global ACTIVE_EVENT SERVERHOST XSCRIPT_SERVER_PORT DEBUG CUR_SEL_PANE XSCRIPTDATARCVD
	    global socketWinName SESSION_STATE WIRESHARK_STORE_DIR WIRESHARK_PATH BROWSER_PATH
		global Solera::HOST Solera::USER Solera::PASS
	    if {!$ACTIVE_EVENT} {return}
	    set selectedIndex [$CUR_SEL_PANE(name) curselection]
	    set sidcidList [split [$CUR_SEL_PANE(name) getcells $selectedIndex,alertID] .]
	    set cnxID [lindex $sidcidList 1]
	    set sensorID [lindex $sidcidList 0]
	    set proto [$CUR_SEL_PANE(name) getcells $selectedIndex,ipproto]
	    set srcIP [$CUR_SEL_PANE(name) getcells $selectedIndex,srcip]
	    set srcPort [$CUR_SEL_PANE(name) getcells $selectedIndex,srcport]
	    set dstIP [$CUR_SEL_PANE(name) getcells $selectedIndex,dstip]
	    set dstPort [$CUR_SEL_PANE(name) getcells $selectedIndex,dstport]
	    if { $CUR_SEL_PANE(format) == "SSN" } {
	       set timestamp [$CUR_SEL_PANE(name) getcells $selectedIndex,starttime]
	    } else {
	       set timestamp [$CUR_SEL_PANE(name) getcells $selectedIndex,date]
	    }   
	    set startTime [clock scan "15 minute" -base [clock scan $timestamp -gmt 1]]
	    set endTime   [clock scan "-15 minute" -base [clock scan $timestamp -gmt 1]]
	    set startTime [clock format $startTime -format {%m.%d.%Y.%H.%M.%S} -gmt 1]
	    set endTime [clock format $endTime -format {%m.%d.%Y.%H.%M.%S} -gmt 1]
		set querySetup "https://$Solera::HOST/ws/artifact-search-flex?user=$Solera::USER&password=$Solera::PASS#path=%2Ftimespan%2F${startTime}.${endTime}%2Fipv4_address%2F${srcIP}_and_${dstIP}"
		switch $proto {
			"6" {
				# TCP
				set queryProto "%2Ftcp_port%2F${srcPort}_and_${dstPort}%2F"
			}
			"17" {
				# UDP
				set queryProto "%2Fudp_port%2F${srcPort}_and_${dstPort}%2F"
			}
			"1" {
				# ICMP
				set queryProto "%2Fip_protocol%2Ficmp%2F"
			}
			default {
				# All Other Protocols
				set queryProto "%2F"
			}
		}
		exec $BROWSER_PATH $querySetup$queryProto &
	}

}