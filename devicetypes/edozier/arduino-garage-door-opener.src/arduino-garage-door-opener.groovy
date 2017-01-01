/**
 *  Arduino Garage Door Opener
 *
 *  Copyright 2016 vint83
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 *  Origin by vint83
 *  Modified by edozier to support LAN connection and tie into the virtual device handler alonge with two door support.
 */

import java.security.MessageDigest;

preferences {
    input("ip", "text", title: "IP Address", description: "ip")
    input("port", "text", title: "Port", description: "port")
    input("mac", "text", title: "MAC Addr", description: "mac")
    input("password", "password", title: "Password", description: "password")
    input("door","text",title:"Door Number", description:"doors")
}

metadata {
    definition (name: "Arduino Garage Door Opener", namespace: "edozier", author: "Everett Dozier") {
      //  Capability "Configuration"
     //  capability "Actuator"
     //  capability "Door Control"
     //  capability "Garage Door Control"
        capability "Contact Sensor"
        capability "Motion Sensor"
        capability "Refresh"
        capability "Sensor"
        capability "Polling"
       // capability "Temperature Measurement"
        attribute "leftDoor", "string"
        attribute "rightDoor", "string"
        attribute "switch", "string"
        	
        
		command "pushLeft"
		command "pushRight"
    }
    
    simulator {
        
    }
    
    tiles {
        standardTile("leftDoor", "device.leftDoor", width: 1, height: 1, canChangeIcon:true, canChangeBackground:true) {
            state("closed", label:'Closed', action:"pushLeft", icon:"st.doors.garage.garage-closed", backgroundColor:"#79b821", nextState:"opening")
            state("open", label:'Open', action:"pushLeft", icon:"st.doors.garage.garage-open", backgroundColor:"#ffa81e", nextState:"closing")
            state("opening", label:'Opening', icon:"st.doors.garage.garage-closed", backgroundColor:"#ffe71e")
            state("closing", label:'Closing', icon:"st.doors.garage.garage-open", backgroundColor:"#ffe71e")
            state("unknown", label:'Unknown', icon:"st.doors.garage.garage-unknown")
            
        }
        standardTile("rightDoor", "device.rightDoor", width: 1, height: 1) {
            state("closed", label:'Closed', action:"pushRight", icon:"st.doors.garage.garage-closed", backgroundColor:"#79b821", nextState:"opening")
            state("open", label:'Open', action:"pushRight", icon:"st.doors.garage.garage-open", backgroundColor:"#ffa81e", nextState:"closing")
            state("opening", label:'Opening', icon:"st.doors.garage.garage-closed", backgroundColor:"#ffe71e")
            state("closing", label:'Closing', icon:"st.doors.garage.garage-open", backgroundColor:"#ffe71e")
            state("unknown", label:'Unknown', icon:"st.doors.garage.garage-unknown")
            
        }
            standardTile("mainDoor", "device.mainDoor", width: 1, height: 1) {
            state("closed", label:'Closed', icon:"st.doors.garage.garage-closed", backgroundColor:"#79b821", nextState:"opening")
            state("open", label:'Open', icon:"st.doors.garage.garage-open", backgroundColor:"#ffa81e", nextState:"closing")
            state("opening", label:'Opening', icon:"st.doors.garage.garage-closed", backgroundColor:"#ffe71e")
            state("closing", label:'Closing', icon:"st.doors.garage.garage-open", backgroundColor:"#ffe71e")
            state("unknown", label:'Unknown', icon:"st.doors.garage.garage-unknown")
            
        }
                 	
        
        main "mainDoor"
        //details(["toggle", "open", "close", "temperature", "refresh"])
         details(["leftDoor", "rightDoor"])
       
    }
}

// gets the address of the hub
private getCallBackAddress() {
    return device.hub.getDataValue("localIP") + ":" + device.hub.getDataValue("localSrvPortTCP")
}

// gets the address of the device
private getHostAddress() {
    def ip = settings.ip
    def port = settings.port
    
    if (!ip || !port) {
        def parts = device.deviceNetworkId.split(":")
        if (parts.length == 2) {
            ip = parts[0]
            port = parts[1]
            log.debug "Using IP: $ip and port: $port for device: ${device.id}"
            return convertHexToIP(ip) + ":" + convertHexToInt(port)
        } else {
            log.warn "Can't figure out ip and port for device: ${device.id}"
        }
    }
    
    log.debug "Using IP: $ip and port: $port for device: ${device.id}"
    return ip + ":" + port
}

private Integer convertHexToInt(hex) {
    return Integer.parseInt(hex,16)
}

private String convertHexToIP(hex) {
    return [convertHexToInt(hex[0..1]),convertHexToInt(hex[2..3]),convertHexToInt(hex[4..5]),convertHexToInt(hex[6..7])].join(".")
}

private String convertIPtoHex(ipAddress) {
    String hex = ipAddress.tokenize( '.' ).collect {  String.format( '%02x', it.toInteger() ) }.join()
    return hex
}

private String convertPortToHex(port) {
    String hexport = port.toString().format( '%04x', port.toInteger() )
    return hexport
}

def refresh() {
    poll()
}

def sendDoorUnknownEvent() {
    state.previousDoorState = "unknown"
    sendEvent(name: "door", value: "unknown", displayed: false)
}

def poll() {
    if(device.deviceNetworkId!=settings.mac) {
        log.debug "setting device network id to device MAC"
        device.deviceNetworkId = settings.mac;
    }
    state.previousLeftDoorState = device.currentValue("leftDoor")
    state.previousRightDoorState = device.currentValue("rightDoor")
    log.debug "Executing 'poll'"
    runIn(30, sendDoorUnknownEvent)
    def hubAction = new physicalgraph.device.HubAction(
        method: "GET",
        path: "/getstatus/",
        headers: [
            HOST: "${getHostAddress()}"
        ]
    )
     
    return hubAction
}

def parse(String description) {
    //log.trace "parse($description)"
    def msg = parseLanMessage(description)
    
    def status = msg.status          // => http status code of the response
    def data = msg.json              // => any JSON included in response body, as a data structure of lists and maps
    log.debug "Received data: ${data}"
    log.debug "Doors: ${data.door.name}"
    log.debug "Doors: ${data.door[0].name}"
    def result = []
    if (status == 200 || status == null) {
        //unschedule sendDoorUnknownEvent
        unschedule()
        state.nonce = data?.nonce
        //left door
        if (!state.previousLeftDoorState) {
            state.previousLeftDoorState = device.currentValue("leftDoor")
        }
        //right door
        if (!state.previousRightDoorState) {
            state.previousRightDoorState = device.currentValue("rightDoor")
        }
        log.debug "parse previousLeftDoorState: ${state?.previousLeftDoorState}"
        log.debug "parse previousRightDoorState: ${state?.previousRightDoorState}"
        // don't send the event if door status haven't changed
        //left door
        if (state.previousLeftDoorState != data?.door[0]?.status) {
        	
            log.debug "door '${data?.door[0]?.name}' status has changed from '${state.previousLeftDoorState}' to '${data?.door[0]?.status}'. sending new event"
            result << createEvent(name: "leftDoor", value: data?.door[0]?.status)
            state.previousLeftDoorState = data?.door[0]?.status
        }
        //right door
         if (state.previousRightDoorState != data?.door[1]?.status) {
            log.debug "door '${data?.door[0]?.name}' status has changed from '${state.previousRightDoorState}' to '${data?.door[1]?.status}'. sending new event"
            result << createEvent(name: "rightDoor", value: data?.door[1]?.status)
            state.previousRightDoorState = data?.door[1]?.status
        }
       result << createEvent(name: "rightDoor", value: data?.door[1]?.status=="closed"?"closed":"open")
    } else {
        result << createEvent(name: "leftDoor", value: "unknown")
        result << createEvent(name: "rightDoor", value: "unknown")
    }
    
    	if (data?.door[0]?.status== "open" || data?.door[1]?.status== "open" ){
    
    result << createEvent(name: "mainDoor", value: "open")

    } else {
    
    result << createEvent(name: "mainDoor", value: "closed")
    }
    
    return result
}

def sha256HashHex(text) {
    return java.security.MessageDigest.getInstance("SHA-256")
    .digest(text.getBytes("UTF-8")).encodeHex()
}

def pushLeft() {
    String pass = "${state.nonce}" + settings.password
    def secret = sha256HashHex(pass)
    log.debug secret
    log.debug "Executing Push Left"
    def hubaction = new physicalgraph.device.HubAction(
        method: "GET",
        path: "/door/toggle/1&${secret}",
        headers: [
            HOST: "${getHostAddress()}"
        ]
    )
    return hubaction
}

def pushRight() {
    String pass = "${state.nonce}" + settings.password
    def secret = sha256HashHex(pass)
    log.debug secret
    log.debug "Executing Push Right"
    def hubaction = new physicalgraph.device.HubAction(
        method: "GET",
        path: "/door/toggle/2&${secret}",
        headers: [
            HOST: "${getHostAddress()}"
        ]
    )
    return hubaction
}




