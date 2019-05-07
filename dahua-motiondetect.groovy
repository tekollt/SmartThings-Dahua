/**
 *  Dahua NVR Motion Detection Switch 
 *
 *  Copyright 2019 ThorE
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License. You may obtain a copy of the License at:
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 *  for the specific language governing permissions and limitations under the License.
 *
 */

metadata {
	definition (name: "Dahua Motion Detection Switch", namespace: "glimte", author: "Thor Egil") {
		capability "Refresh"
		capability "Switch"
		capability "Health Check"

		capability "Actuator"

		command "clearDigestAuthData"
	}

	tiles(scale: 2) {
		standardTile("switchDisplayAction", "device.switch", inactiveLabel: true, width:6, height:1, decoration: "flat") {
			state "unknown", label:'check configuration', icon:"st.Entertainment.entertainment9", backgroundColor:"#e50000"
			state "turningon", label:'turning on', icon:"st.Entertainment.entertainment9", backgroundColor:"#00a0dc", nextState:"on"
			state "on", label:'${name}', action:"off", icon:"st.Entertainment.entertainment9", backgroundColor:"#00a0dc", nextState:"turningoff"
			state "turningoff", label:'turning off', icon:"st.Entertainment.entertainment9", backgroundColor:"#ffffff", nextState:"off"
			state "off", label:'${name}', action:"on", icon:"st.Entertainment.entertainment9", backgroundColor:"#ffffff", nextState:"turningon"
		}
		standardTile("refresh", "device.switch", width: 2, height: 2, decoration: "flat") {
			state "icon", action:"refresh", icon:"st.secondary.refresh", defaultState: true
		}
		standardTile("clearDigestAuthData", "device.switch", width: 2, height: 2, decoration: "flat") {
			state "icon", action:"clearDigestAuthData", icon:"st.Office.office10", defaultState: true
		}
		standardTile("force_off", "device.button", width: 1, height: 1, decoration: "flat") {
			state "icon", action: "off", icon: "st.Entertainment.entertainment9", label: 'Force Off', defaultState: true
		}
		standardTile("force_on", "device.switch", width: 1, height: 1, decoration: "flat") {
			state "icon", action: "on", icon: "st.Entertainment.entertainment9", label: 'Force On', defaultState: true
        }    
		main "switchDisplayAction"
		details(["switchDisplayAction", "refresh", "force_on", "force_off"])
	}

	preferences {
		input name: "tcpIP", type: "text", title: "Device IP", description: "IP of the Dahua Device", displayDuringSetup: true, required: true
		input name: "tcpPort", type: "text", title: "TCP Port", description: "TCP port of the Dahua Device", displayDuringSetup: true, required: false
		input name: "cameraChannel", type: "text", title: "Camera Channel", description: "Channel of the camera", displayDuringSetup: true, required: false		
        input name: "username", type: "text", title: "Username", description: "Username of the device", displayDuringSetup: true, required: true
        input name: "password", type: "password", title: "Password", description: "Password of the device", displayDuringSetup: true, required: false

	}
}

def installed() {
	log.debug("installed()")
	sendEvent(name:"switch", value:"unknown")
}

def updated() {
	log.debug("updated()")

	if (state.tcpIP != tcpIP) {
		state.tcpIP = tcpIP
		log.debug("New Device IP: ${state.tcpIP}")
	}
	
	if 	(state.tcpPort != tcpPort && tcpPort != null) {
			state.tcpPort = tcpPort
			log.debug("New device port: ${state.tcpPort}")
	} else {
		state.tcpPort = "80"
		log.debug("using default port: ${state.tcpPort}")

	}

	if (state.cameraChannel != cameraChannel && cameraChannel != null) {
		state.cameraChannel = cameraChannel
		log.debug("New Camera Channel: ${state.CameraChannel}")
	} else {
		state.cameraChannel = "0"
		log.debug("Using default Camera Channel: ${state.CameraChannel}")
	}


	if (state.username != username && username != null) {
		state.username = username
		log.debug("New Device Username")
		clearDigestAuthData()
	} else {
		state.username = "admin"
		log.debug("Using default username: ${state.username}")
	}

	if (state.password != password) {
		state.password = password
		log.debug("New device Password")
		clearDigestAuthData()
	}

	// Ping the NVR every 5 minutes for health-check purposes
	unschedule()
	runEvery5Minutes(refresh)
	// After checkInterval seconds have gone by, ST sends one last ping() before marking as offline
	// set checkInterval to the length of 2 failed refresh()es (plus an extra minute)
	sendEvent(name: "checkInterval", value: 2 * 5 * 60 + 60, displayed: false, data: [protocol : "LAN"])

	refresh()
}

def parseResponse(physicalgraph.device.HubResponse response) {
	log.debug("parseResponse()")
	return parse(response.description)
}

def getMotionDetectUrl() {
	return "/cgi-bin/configManager.cgi?action=getConfig&name=MotionDetect[${state.cameraChannel}].Enable"
}

def setMotionDetectTrueUrl() {
	return "/cgi-bin/configManager.cgi?action=setConfig&MotionDetect[${state.cameraChannel}].Enable=true"
}

def setMotionDetectFalseUrl() {
	return "/cgi-bin/configManager.cgi?action=setConfig&MotionDetect[${state.cameraChannel}].Enable=false"
}

def parse(String description) {
	log.debug("parse()")
	def msg = parseLanMessage(description)

	// Handle unknown responses
	if (!state.lastRequest || state.lastRequest.requestId != msg.requestId) {
		log.debug("parse() received message likely meant for other device handler (requestIds don't match): ${msg}")
		return
	}

	if (msg.status == 200) {
		// Delete last request info since it succeeded
		def lastRequest = state.lastRequest
		// def getMotionDetectUrl = "/cgi-bin/configManager.cgi?action=getConfig&name=MotionDetect[${state.cameraChannel}].Enable"
		// def setMotionDetectTrueUrl = "/cgi-bin/configManager.cgi?action=setConfig&MotionDetect[${state.cameraChannel}].Enable=true"
		// def setMotionDetectFalseUrl = "/cgi-bin/configManager.cgi?action=setConfig&MotionDetect[${state.cameraChannel}].Enable=false"
		state.remove("lastRequest")

		// use lastRequest uri to decide how to handle response
		if (lastRequest.uri.endsWith("/information")) {
			handleInformationResponse(msg)
			return
		}
		else if (lastRequest.uri.endsWith(getMotionDetectUrl())) {
			handleVideoanalysisResponse(msg, lastRequest)
			return
		}

		else if (lastRequest.uri.endsWith(setMotionDetectTrueUrl())) {
			handleVideoanalysisResponse(msg, lastRequest)
			return
		}
		else if (lastRequest.uri.endsWith(setMotionDetectFalseUrl())) {
			handleVideoanalysisResponse(msg, lastRequest)
			return
		}
		else {
			log.debug("Not sure how to handle response from ${lastRequest.uri}")
		}
	}
	else if (msg.status == 401) {
		// NEED MORE AUTH
		handleNeedsAuthResponse(msg)
		return
	}
	else {
		log.debug("parse() received failure message: ${msg}")
	}
}

def ping() {
	log.debug("ping()")
	healthCheck()
}

def refresh() {
	log.debug("refresh()")
	checkMotionDetectionSetting()
}

def healthCheck() {
	log.debug("healthCheck()")
	// def getMotionDetectUrl = "/cgi-bin/configManager.cgi?action=getConfig&name=MotionDetect[${state.cameraChannel}]"
	def action = createCameraRequest("GET", getMotionDetectUrl())
	sendHubCommand(action)
}

// Response handlers
def handleInformationResponse(response) {
	log.debug("handleInformationResponse(): ${response.data}")
}

def handleVideoanalysisResponse(response, lastRequest) {
	log.debug("handleVideoanalysisResponse()")
	def state = "unknown"
	if (lastRequest.method == "GET") {
		// log.debug("Responsdata debug: ${response}")
		// def detectionType = response.data['body']
		// log.debug("detectionType: ${response.data}" testTrailingSpace)
		def detectionType = response.body.toString().trim()
        
		if (cameraChannel == null) {
        def detectionString = ("table.MotionDetect[0].Enable=false").toString()
        state = (detectionType == detectionString ? "off" : "on")
        } else {
        def detectionString = ("table.MotionDetect[${cameraChannel}].Enable=false").toString()
        state = (detectionType == detectionString ? "off" : "on")
        }
		//def detectionString = ("table.MotionDetect[${cameraChannel}].Enable=false").toString()
        // log.debug("respons.body: ${response.body}")
		//state = (detectionType == detectionString ? "off" : "on")
        log.debug("detectionType: ${detectionType}")
		// log.debug("state: ${state}")
	}
	else if (lastRequest.method == "PUT") {
		// resonse.data is empty on PUT success, we must use lastRequest data
		def detectionType = lastRequest.payload['Enable']
		state = (detectionType == "false" ? "off" : "on")
	}
	log.debug("Motion detection is now ${state}")
	sendEvent(name:"switch", value:state)
}

def handleNeedsAuthResponse(msg) {
	log.debug("needsAuthResponse(), headers: ${msg.headers}, requestId: ${msg.requestId}")

	// Parse out the digest auth fields
	def wwwAuthHeader = msg.headers['www-authenticate']
	handleWWWAuthenticateHeader(wwwAuthHeader)

	// Retry the request if we haven't already
	if (!state.lastRequest || state.lastRequest.isRetry) {
		return
	}

	retryLastRequest([requestId: msg.requestId])
}

def retryLastRequest(data) {
	log.debug("retryLastRequest(), requestId: ${data.requestId}")
	if (!state.lastRequest || state.lastRequest.isRetry || state.lastRequest.requestId != data.requestId) {
		log.debug("Error: failed attempting to retry a request. lastRequest: ${state.lastRequest}")
		return
	}
	log.debug("About to retry lastRequest: ${state.lastRequest}")
	def action = createCameraRequest(state.lastRequest.method, state.lastRequest.uri, state.lastRequest.useAuth, state.lastRequest.payload, true)
	// log.debug("Created retry request: ${action}")
	sendHubCommand(action)
}

def checkMotionDetectionSetting() {
	log.debug("checkMotionDetectionSetting()")
	// def getMotionDetectUrl = "/cgi-bin/configManager.cgi?action=getConfig&name=MotionDetect[${state.cameraChannel}].Enable"
    def action = createCameraRequest("GET", getMotionDetectUrl(), true)
	//def action = createCameraRequest("GET", "/cgi-bin/configManager.cgi?action=getConfig&name=MotionDetect[0].Enable", true)
	// log.debug("checking motion detection setting with request: ${action}")
	sendHubCommand(action)
}

def setMotionDetectionSettingEnabled(on) {
    def detectionType = on ? "true" : "false"
	// def setMotionDetectTrueUrl = "/cgi-bin/configManager.cgi?action=setConfig&MotionDetect[${state.cameraChannel}].Enable=true"
	def action = createCameraRequest("PUT", setMotionDetectTrueUrl(), true, [Enable : detectionType])
	//log.debug("Setting motion detection setting ${on} with request: ${action}")
	sendHubCommand(action)
}
def setMotionDetectionSettingDisabled(off) {
    def detectionType = off ? "false" : "true"
	// def setMotionDetectFalseUrl = "/cgi-bin/configManager.cgi?action=setConfig&MotionDetect[${state.cameraChannel}].Enable=false"
	def action = createCameraRequest("PUT", setMotionDetectFalseUrl(), true, [Enable : detectionType])
	//log.debug("Setting motion detection setting ${off} with request: ${action}")
	sendHubCommand(action)
}
def on() {
	log.debug("on()")
	setMotionDetectionSettingEnabled(true)
}

def off() {
	log.debug("off()")
	setMotionDetectionSettingDisabled(true)
}

def clearDigestAuthData() {
	log.debug("Clearing digest auth data.")
	state.remove("digestAuthFields")
	state.remove("lastRequest")
}

private physicalgraph.device.HubAction createCameraRequest(method, uri, useAuth = false, payload = null, isRetry = false) {
	log.debug("Creating camera request with method: ${method}, uri: ${uri}, payload: ${payload}, isRetry: ${isRetry}")

	if (state.tcpIP == null || state.password == null) {
		log.debug("Cannot check motion detection status, IP address or password is not set.")
		return null
	}

	try {
		def headers = [
			HOST: "${state.tcpIP}:${state.tcpPort}"
		]
		if (useAuth && state.digestAuthFields) {
			// Increment nonce count and generate new client nonce (cheat: just MD5 the nonce count)
			if (!state.digestAuthFields.nc) {
				// log.debug("Resetting nc to 1")
				state.digestAuthFields.nc = 1
			}
			else {
				state.digestAuthFields.nc = (state.digestAuthFields.nc + 1) % 1000
				// log.debug("Incremented nc: ${state.digestAuthFields.nc}")
			}
			state.digestAuthFields.cnonce = md5("${state.digestAuthFields.nc}")
			// log.debug("Updated cnonce: ${state.digestAuthFields.cnonce}")

			headers.Authorization = generateDigestAuthHeader(method, uri)
		}

		def data = [
			method: method,
			path: uri,
			headers: headers
		]
		if (payload) {
			data.body = payload
		}

		// Use a custom callback because this seems to bypass the need for DNI to be hex IP:port or MAC address
		def action = new physicalgraph.device.HubAction(data, null, [callback: parseResponse])
		// log.debug("Created new HubAction, requestId: ${action.requestId}")

		// Persist request info in case we need to repeat it
		state.lastRequest = [:]
		state.lastRequest.method = method
		state.lastRequest.uri = uri
		state.lastRequest.useAuth = useAuth
		state.lastRequest.payload = payload
		state.lastRequest.isRetry = isRetry
		state.lastRequest.requestId = action.requestId

		return action
	}
	catch (Exception e) {
		log.debug("Exception creating HubAction for method: ${method} and URI: ${uri}")
	}
}

private void handleWWWAuthenticateHeader(header) {
	log.debug("handleWWWAuthenticateHeader()")
	// Create digestAuthFields map if it doesn't exist
	if (!state.digestAuthFields) {
		state.digestAuthFields = [:]
	}

	// `Digest realm="iPolis", nonce="abc123", qop="auth"`
	header.tokenize(',').collect {
		def tokens = it.trim().tokenize('=')
		if (tokens[0] == "Digest realm") tokens[0] = "realm"
		state.digestAuthFields[tokens[0]] = tokens[1].replaceAll("\"", "")
	}
	// log.debug("Used authenticate header (${header}) to update digestAuthFields: ${state.digestAuthFields}")
}

private String generateDigestAuthHeader(method, uri) {
	/*
	HA1=MD5(username:realm:password)
	HA2=MD5(method:digestURI)
	response=MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
	*/
	def ha1 = md5("${state.username}:${state.digestAuthFields.realm}:${state.password}")
	// log.debug("ha1: ${ha1} (${state.username}:${state.digestAuthFields.realm}:${state.password})")

	def ha2 = md5("${method}:${uri}")
	// log.debug("ha2: ${ha2} (${method}:${uri})")

	def digestAuth = md5("${ha1}:${state.digestAuthFields.nonce}:${state.digestAuthFields.nc}:${state.digestAuthFields.cnonce}:${state.digestAuthFields.qop}:${ha2}")
	// log.debug("digestAuth: ${digestAuth} (${ha1}:${state.digestAuthFields.nonce}:${state.digestAuthFields.nc}:${state.digestAuthFields.cnonce}:${state.digestAuthFields.qop}:${ha2})")
	def authHeader = "Digest username=\"${state.username}\", realm=\"${state.digestAuthFields.realm}\", nonce=\"${state.digestAuthFields.nonce}\", uri=\"${uri}\", qop=\"${state.digestAuthFields.qop}\", nc=\"${state.digestAuthFields.nc}\", cnonce=\"${state.digestAuthFields.cnonce}\", response=\"${digestAuth}\""
	return authHeader
}

// Utilities
private String md5(String str) {
	def digest = java.security.MessageDigest.getInstance("MD5").digest(str.getBytes("UTF-8"))
	return digest.encodeHex() as String
}