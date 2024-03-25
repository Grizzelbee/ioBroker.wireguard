'use strict';

/*
 * Created with @iobroker/create-adapter v2.0.2
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');

// Load your modules here, e.g.:
const {Client}       = require('ssh2');
const timeOuts   = [];
const settingsPeerMap= {};
let adapter      = null;


class Wireguard extends utils.Adapter {

    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: 'wireguard',
            _ifaceOnlineState : {}
        });

        this.on('ready', this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('unload', this.onUnload.bind(this));

        // let _ifaceOnlineState;
    }

    async onStateChange(id, state){
        if (state) {
            // The state was changed
            // this.log.info(`state ${id} changed: ${state.val} (ack = ${state.ack})`);
            if (!state.ack) {
                // manual change / request
                let hostaddress = '';
                let user        = '';
                let pass        = '';
                let configFile  = '';
                let port        = 22;
                let container   = '';
                const path = id.split('.', 5).join('.');
                const iFace = id.split('.', 3).pop().split('-').pop();
                const peer = id.split('.', 5).pop();
                const searchHost = id.split('.', 3).pop().split('-', 1).pop();
                const requestedAction = id.split('.').pop();
                for (let host=0; host < this.config.hosts.length; host++) {
                    if (this.config.hosts[host].name === searchHost) {
                        hostaddress = this.config.hosts[host].hostaddress;
                        container   = this.config.hosts[host].container;
                        port = this.config.hosts[host].port;
                        user = this.config.hosts[host].user;
                        pass = this.config.hosts[host].password;
                        break;
                    }
                }
                adapter.log.debug(`Received request to ${requestedAction}.`);
                if ('suspend_Peer' === requestedAction){
                    await adapter.suspendPeer(hostaddress, port, path, user, pass, iFace, peer, container);
                } else if ('restore_Peer' === id.split('.').pop()){
                    adapter.log.info(`Path: ${path+'.allowedIps.0'}`);
                    adapter.getState(path+'.allowedIps.0', function (err, state){
                        if (!err && state) {
                            adapter.log.info(`Restoring peer ${peer} with IP ${state.val} on interface ${iFace}.`);
                            adapter.restorePeer(hostaddress, port, id.split('.', 5).join('.'), user, pass, iFace, peer, state.val, container);
                        }
                    });
                } else if ('restore_all_Peers' === id.split('.').pop()){
                    adapter.log.info(`Restoring all peers for interface ${iFace} on host ${searchHost}`);
                    for (let i=0; i < this.config.configFiles.length; i++) {
                        adapter.log.info(`Config: iFace=${this.config.configFiles[i].iFace}, host=${this.config.configFiles[i].hostName}`);
                        if ((this.config.configFiles[i].hostName === searchHost) && (this.config.configFiles[i].iFace === iFace) ){
                            configFile = this.config.configFiles[i].configFile;
                            break;
                        }
                    }
                    await adapter.restoreAllPeers(hostaddress, port, user, pass, iFace, configFile, container);
                }
            }
        }
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Reset the connection indicator during startup
        await this.setState('info.connection', true, true);
        // Initialize your adapter here
        adapter = this; // preserve adapter reference to address functions etc. correctly later
        const settings = this.config;
        if (settings.hosts.length === 1){
            this.log.info(`There is ${settings.hosts.length} wireguard host to monitor.`);
        } else {
            this.log.info(`There are ${settings.hosts.length} wireguard hosts to monitor.`);
        }
        // build a hashmap for the username/device settings to get easier access to it later
        for (let n= 0; n < settings.names.length; n++){
            settingsPeerMap[settings.names[n].pubKey] = {'user':'user', 'device':'device', 'desc':'description'};
            settingsPeerMap[settings.names[n].pubKey].user = settings.names[n].user;
            settingsPeerMap[settings.names[n].pubKey].desc = settings.names[n].groupname;
            settingsPeerMap[settings.names[n].pubKey].device = settings.names[n].device;
        }
        // get all already known interfaces from device tree
        adapter._knownInterfaces = await adapter.getKnownInterfaces();
        adapter.log.debug(`_knownInterfaces=${JSON.stringify(adapter._knownInterfaces)}`);
        try{
            for (let host=0; host < settings.hosts.length; host++) {
                timeOuts.push(setInterval(async function pollHost() {
                    await adapter.getWireguardInfos(settings.hosts[host].name, settings.hosts[host].hostaddress, settings.hosts[host].port, settings.hosts[host].user, settings.hosts[host].password, settings.hosts[host].sudo, settings.hosts[host].docker)
                        .then((wgRawData) => {
                            adapter.parseWireguardInfosToJson(wgRawData)
                                .then((wgJson)=>{
                                    adapter.updateDevicetree(settings.hosts[host].name, wgJson);
                                })
                                .catch((err)=>{
                                    adapter.log.warn(err);
                                });
                        })
                        .catch((err)=>{
                            adapter.log.warn(err);
                            adapter.setAllKnownInterfacesOffline(settings.hosts[host].name);
                        });
                }, 1000 * settings.hosts[host].pollInterval));
            }
            for (let n=0; n < timeOuts.length; n++){
                this.log.info(`Started ${settings.hosts[n].pollInterval} seconds monitoring interval for host [${settings.hosts[n].name}]`);
            }
        } catch(error)  {
            this.log.error(error);
            await this.setState('info.connection', false, true);
        }
    }

    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            for (let n=0; n<timeOuts.length; n++){
                adapter.log.info(`Clearing interval for host [${adapter.config.hosts[n].name}]`);
                clearInterval(timeOuts[n]);
            }
            callback();
        } catch (e) {
            callback();
        }
    }

    /**
     *
     * @param hostaddress {string} Host address of the host to run this command on
     * @param port {number}
     * @param user {string} encrypted username for the host
     * @param pass{string} encrypted password for the host
     * @param command{string} the command to execute on this host
     * @returns {Promise<unknown>}
     */
    async execCommand(hostaddress, port, user, pass, command){
        return new Promise((resolve, reject) => {
            adapter.log.debug(`Trying to reach host ${hostaddress}.`);
            const conn = new Client();
            // Event handler if connection is in state "onReady"
            conn.on('ready', () => {
                adapter.log.debug('ssh client :: authenticated');
                adapter.log.debug(`Executing command [${command}] on host ${hostaddress}.`);
                conn.exec(command, {
                    term: process.env.TERM,
                    rows: process.stdout.rows,
                    cols: process.stdout.columns
                }, (error, responseStream) => {
                    if (error) reject(error);
                    let rawdata = '';
                    responseStream.on('close', () => {
                        adapter.log.debug('Stream :: close');
                        conn.end();
                        adapter.log.debug(`received rawdata: ${rawdata}`);
                        resolve(rawdata);
                    })
                        .on('data', (data) => {
                            // collect and assemble all data from stream
                            rawdata += data;
                        });
                });
            });
            // Event handler if connection fails and throws an error
            conn.on('error', function (error) {
                adapter.log.debug('ssh client :: An error occurred: ' + error);
                reject(error);
            });
            // connect to host
            adapter.log.debug(`Connecting to host: [${hostaddress}] on port ${port}`);
            conn.connect({
                host: hostaddress,
                port: port,
                username: user,
                password: pass
            });
        });
    }


    /**
     * Opens an ssh connection to the given host, executes the wg-json command and returns the output data of that command.
     *
     * @param {string} hostname symbolic name of the host
     * @param {string} hostaddress IP address of the host
     * @param {number} port SSH port of the host
     * @param {string} user username which is used to connect to the host
     * @param {string} pass password for the user
     * @param {boolean} sudo indicator whether sudo should be used
     * @param {boolean} docker indicator whether sudo should be used
     * @returns {Promise<JSON|string>} returns a json structure when successful or an error message
     */
    async getWireguardInfos(hostname, hostaddress, port, user, pass, sudo, docker) {
        adapter.log.debug(`Retrieving WireGuard status of host [${hostname}] on address [${hostaddress}]`);
        let command = docker ? 'docker exec -it wireguard /usr/bin/wg show all dump' : 'wg show all dump';
        command = sudo ? 'sudo ' + command : command;
        return new Promise(function(resolve, reject) {
            adapter.execCommand(hostaddress, port, user, pass, command)
                .then((result) => {
                    resolve(result);
                })
                .catch((error) => {
                    reject(error);
                });
        });
    }


    /**
     *
     * @param command {string}
     * @param hostaddress {string}
     * @param container {string}
     * @returns {string|*}
     */
    getExtendedCommand(command, hostaddress, container){
        for (let i=0; i < adapter.config.hosts.length; i++){
            if (adapter.config.hosts[i].hostaddress === hostaddress){
                command = adapter.config.hosts[i].docker? `docker exec -it ${container} /usr/bin/${command}` : command;
                command = adapter.config.hosts[i].sudo? 'sudo '+command : command;
                return command;
            }
        }
        throw new Error(`Command couldn't be extended: ${command}`);
    }


    /**
     *
     * @param hostaddress {string}
     * @param path {string}
     * @param {number} port SSH Port at the server
     * @param user {string}
     * @param pass {string}
     * @param iFace {string}
     * @param peer {string}
     * @param container {string}
     * @returns {Promise<unknown>}
     */
    suspendPeer(hostaddress, port, path, user, pass, iFace, peer, container){
        adapter.log.info(`Suspending peer [${adapter.getUserByPeer(peer)}-${adapter.getDeviceByPeer(peer)}] of interface ${iFace} on host ${hostaddress}.`);
        return new Promise(function(resolve, reject) {
            const command = adapter.getExtendedCommand(`wg set ${iFace} peer ${peer} remove`, hostaddress, container);
            adapter.execCommand(hostaddress, port, user, pass, command)
                .then((result) => {
                    adapter.setState(path+'.connected', false, true);
                    adapter.setState(path+'.isSuspended', true, true);
                    resolve(result);
                })
                .catch((error) => {
                    reject(error);
                });
        });
    }


    /**
     *
     * @param hostaddress {string}
     * @param {number} port SSH Port at the server
     * @param path {string}
     * @param user {string}
     * @param pass {string}
     * @param iFace {string}
     * @param peer {string}
     * @param ip {string}
     * @param container {string}
     * @returns {Promise<unknown>}
     */
    restorePeer(hostaddress, port, path, user, pass, iFace, peer, ip, container){
        adapter.log.info(`Restoring peer [${adapter.getUserByPeer(peer)}-${adapter.getDeviceByPeer(peer)}] of interface ${iFace} on host ${hostaddress} with IP [${ip}].`);
        return new Promise(function(resolve, reject) {
            const command = adapter.getExtendedCommand(`wg set ${iFace} peer ${peer} allowed-ips ${ip}`, hostaddress, container);
            adapter.execCommand(hostaddress, port, user, pass, command)
                .then((result) => {
                    adapter.setState(path+'.connected', true, true);
                    adapter.setState(path+'.isSuspended', false, true);
                    resolve(result);
                })
                .catch((error) => {
                    reject(error);
                });
        });
    }


    /**
     *
     * @param hostaddress {string}
     * @param {number} port SSH Port at the server
     * @param user {string}
     * @param pass {string}
     * @param iFace {string}
     * @param configFile {string}
     * @param container {string}
     * @returns {Promise<void>}
     */
    async restoreAllPeers(hostaddress, port, user, pass, iFace, configFile, container){
        const command = adapter.getExtendedCommand(`wg syncconf ${iFace} ${configFile}`, hostaddress, container);
        adapter.execCommand(hostaddress, port, user, pass, command)
            .then((result) => {
                return result;
            })
            .catch((error) => {
                throw new Error(error);
            });
    }

    /**
     * parses the commandline output of the wg show all dump command and parses it into a json structure
     *
     * @param wgRawData {string} commandline output of wg show all dump command
     * @returns {Promise<{JSON}>} returns the parsed json object
     */
    async parseWireguardInfosToJson(wgRawData){
        const connectedPeers = [];
        const connectedUsers = [];
        const data = wgRawData.split('\n');
        // adapter.log.debug(`RawData has ${data.length} lines`);
        for (let n = 0; n < data.length; n++) {
            data[n] = data[n].split('\t');
        }
        adapter.log.debug(`Workdata: ${JSON.stringify(data)}`);
        // first row holds server data; rest are peers; last one is empty
        const wg = {};
        for ( let i=0; i<data.length; i++ ) {
            let iFace;
            if ( i===0 || (data[i][0] !== data[i-1][0]) ){
                if (data[i][0] === '') break;
                iFace = data[i][0];
                adapter.log.debug(`New Interface: ${iFace}. Initialize object.`);
                wg[iFace]= {};
                // wg[iFace].privateKey = data[i][1]; // don't show the private key of the interface in ioBroker
                wg[iFace].publicKey= data[i][2];
                wg[iFace].listenPort = data[i][3];
                wg[iFace].fwmark = data[i][4];
                wg[iFace].peers = {};
                wg[iFace].users = {};
            } else {
                // data fields: interface public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
                // data fields: [0]       [1]        [2]           [3]      [4]         [5]              [6]         [7]         [8]
                iFace = data[i][0];
                const peer = data[i][1];
                const user = adapter.getUserByPeer(peer);
                const device = adapter.getDeviceByPeer(peer);
                adapter.log.silly(`New Peer ${peer} for interface ${ iFace }`);
                wg[iFace].peers[peer] = {};
                wg[iFace].peers[peer].user = user;
                wg[iFace].peers[peer].device = device;
                wg[iFace].peers[peer].presharedKey = data[i][2];
                wg[iFace].peers[peer].endpoint = data[i][3];
                wg[iFace].peers[peer].allowedIps = data[i][4].split(',');
                wg[iFace].peers[peer].latestHandshake = data[i][5];
                wg[iFace].peers[peer].connected = adapter.isPeerOnline(data[i][5]);
                wg[iFace].peers[peer].transferRx = data[i][6];
                wg[iFace].peers[peer].transferTx = data[i][7];
                wg[iFace].peers[peer].persistentKeepalive = data[i][8];
                if (wg[iFace].peers[peer].connected) connectedPeers.push(peer);
                if (wg[iFace].peers[peer].connected) {
                    if (!connectedUsers.includes(user)) connectedUsers.push(user);
                }
                // build users perspective
                if (user && (user !== '') && (user.at(-1) !== '.') ) {
                    // there is a username
                    if ( Object.prototype.hasOwnProperty.call(wg[iFace].users, user) ){
                        // there is already a connected state
                        wg[iFace].users[user].connected = ( wg[iFace].users[user].connected || wg[iFace].peers[peer].connected );
                    } else {
                        // create new connected state
                        wg[iFace].users[user] = {'connected' : wg[iFace].peers[peer].connected};
                    }
                    if (device && (device !== '') && (device.at(-1) !== '.') ) {
                        wg[iFace].users[user][device] = wg[iFace].peers[peer].connected ;
                    } else {
                        adapter.log.debug(`There is no device defined for public key: [${peer}] - or it's name is ending in a dot. Skipped creating user object.`);
                    }
                } else {
                    adapter.log.debug(`There is no user defined for public key: [${peer}] - or it's name is ending in a dot. Skipped creating user object.`);
                }
            }
            wg[iFace].connectedPeers = connectedPeers.join(', ');
            wg[iFace].connectedPeersCount = connectedPeers.length;
            wg[iFace].connectedUsers = connectedUsers.join(', ');
            wg[iFace].connectedUsersCount = connectedUsers.length;
        }
        return(wg);
    }

    /**
     * Translates the publicKey of a peer to its symbolic name in config.
     *
     * @param peerId {string} The public Key to translate
     * @returns {string} symbolic name of the peer or the public key if no name was found
     */
    getUserByPeer(peerId){
        // adapter.log.debug(`calling getUserByPeer with peerId ${peerId}`);
        if (settingsPeerMap[peerId]){
            if (Object.prototype.hasOwnProperty.call(settingsPeerMap[peerId], 'user') ){
                // adapter.log.debug('SettingsPeerMap.user is available. Returning ' + settingsPeerMap[peerId].user);
                return settingsPeerMap[peerId].user;
            } else return '';
        } else return '';
    }

    /**
     * Translates the publicKey of a peer to its symbolic device name in config.
     *
     * @param peerId {string} The public Key to translate
     * @returns {string} symbolic device name of the peer or the public key if no name was found
    */
    getDeviceByPeer(peerId){
        if (settingsPeerMap[peerId]){
            if (Object.prototype.hasOwnProperty.call(settingsPeerMap[peerId], 'device') ){
                return settingsPeerMap[peerId].device;
            } else {
                return '';
            }
        } else return '';
    }

    /**
     * Translates the publicKey of a peer to its symbolic device name in config.
     *
     * @param peerId {string} The public Key to translate
     * @returns {string} symbolic device name of the peer or the public key if no name was found
     */
    getDescByPeer(peerId){
        if (settingsPeerMap[peerId]){
            // adapter.log.debug(`getDescByPeer: Found config for ${peerId}`);
            if ( Object.prototype.hasOwnProperty.call(settingsPeerMap[peerId], 'user') || Object.prototype.hasOwnProperty.call(settingsPeerMap[peerId], 'device')){
                // initialize string
                let result = '';
                if ( Object.prototype.hasOwnProperty.call(settingsPeerMap[peerId], 'user') ) {
                    // add user to result if there is some
                    result += settingsPeerMap[peerId].user;
                    if (Object.prototype.hasOwnProperty.call(settingsPeerMap[peerId], 'device')) {
                        // add device to result if there is some - and add a blank if there is already a user
                        result += (result.length > 0 ? ' ' : '') + settingsPeerMap[peerId].device;
                        return result;
                    }
                }
            }
        } else {
            adapter.log.silly(`getDescByPeer: Unknown peerId ${peerId}`);
            return '';
        }
    }

    /**
     * tests whether the peer is online
     *
     * @param tsValue the latest Handshake of the peer
     * @returns {boolean} true if the peer has been connected in the last 130 Secs; false if not
     */
    isPeerOnline(tsValue){
        if (tsValue) {
            return (new Date() - new Date(tsValue*1000)) < 130000;
        } else return false;
    }


    /**
     * Function Create or extend object
     *
     * Updates an existing object (id) or creates it if not existing.
     * In case id and name are equal, it will only set it's new state
     *
     * @param id {string} path/id of datapoint to create
     * @param objData {object} details to the datapoint to be created (Device, channel, state, ...)
     * @param value {any} value of the datapoint
     */
    createOrExtendObject(id, objData, value) {
        if (value && ('undefined' !== typeof value) ){
            adapter.getObject(id, function (err, oldObj) {
                if (!err && oldObj) {
                    if ( objData.common.name === oldObj.common.name && objData.common.icon === oldObj.common.icon){
                        // adapter.log.debug(`Same object detected: ${objData.common.name} vs. old group name: ${oldObj.common.name}`);
                        adapter.setState(id, value, true);
                    } else{
                        // adapter.log.debug(`New group name detected: ${objData.common.name} vs. old group name: ${oldObj.common.name}`);
                        adapter.extendObject(id, objData, () => {adapter.setState(id, value, true);});
                    }
                } else {
                    adapter.setObjectNotExists(id, objData, () => {adapter.setState(id, value, true);});
                }
            });
        }
    }


    /**
     * sets the connected state of a peer and also creates the syspend_Peer button and the isSuspended indicator
     *
     * @param {string} path path to the peer in object tree
     * @param {boolean} value value to set
     */
    setConnectedState(path, value) {
        adapter.createOrExtendObject(`${path}.suspend_Peer`, {
            type: 'state',
            common: {
                name: `Suspend this peer temporarily.`,
                // 'icon':''
                'read': false,
                'write': true,
                'type': 'boolean',
                'role':'button'
            }
        }, true);
        adapter.subscribeStates(`${path}.suspend_Peer`);
        adapter.createOrExtendObject(`${path}.restore_Peer`, {
            type: 'state',
            common: {
                name: `Bring that temporarily suspended peer back into action.`,
                // 'icon':''
                'read': false,
                'write': true,
                'type': 'boolean',
                'role':'button'
            }
        }, true);
        adapter.subscribeStates(`${path}.restore_Peer`);
        adapter.createOrExtendObject(`${path}.connected`, {
            type: 'state',
            common: {
                name: 'Peer is connected',
                // 'icon':''
                'read': true,
                'write': false,
                'role': 'indicator.reachable',
                'type': 'boolean'
            }
        }, value);
        adapter.createOrExtendObject(`${path}.isSuspended`, {
            type: 'state',
            common: {
                name: `Indicates whether this peer is currently suspended.`,
                // 'icon':''
                'read': true,
                'write': false,
                'type': 'boolean',
                'role':'indicator'
            }
        }, false); // !knownPeers.includes( path.split('.', 5).pop() ) );
    }

    /**
     * Navigates through the given object and build the device tree out of it.
     *
     * @param {string} path path inside the ioBroker object tree
     * @param {object} obj the object to handle
     */
    extractTreeItems(path, obj ){
        let finalValue;
        // build key-value pairs from object structure
        for (const [key, value] of Object.entries(obj) ) {
            // adapter.log.debug(`Key ${key}: Value ${value} | typeof value ${ typeof value}`);
            finalValue = value;
            const obj = {
                type: 'state',
                common: {
                    name: key,
                    // 'icon':''
                    'read': true,
                    'write': false,
                    'role':'value',
                    'type': typeof value
                }
            };
            // handle some special fields to add units or roles
            switch (key){
                case 'transferRx' :
                case 'transferTx' : {
                    obj.common.unit='bytes';
                    break;
                }
                case 'endpoint': obj.common.role='info.ip';
                    break;
                case 'connectedUsers':
                case 'connectedPeers': {
                    obj.common.role='text';
                    break;
                }
                case 'listenPort': obj.common.role='info.port';
                    break;
                case 'latestHandshake':{
                    obj.common.role='date';
                    obj.common.type='number';
                    finalValue = Number(value*1000); // convert unix time to utc
                    break;
                }
                case 'connected':
                    obj.common.role='indicator.reachable';
                    obj.common.type='boolean';
                    if (path.split('.').includes('peers')) adapter.setConnectedState(path, value);
                    break;
            }
            // If there is an object inside the given structure, dive one level deeper
            if (typeof value === 'object') {
                // It's an object - so iterate deeper
                obj.type = 'group';
                obj.role = '';
                switch ( obj.common.name ) {
                    case 'peers' :
                        obj.common.name='Peers by public key';
                        obj.common.icon='icons/peers.svg';
                        break;
                    case 'users' :
                        obj.common.name='Connect-states of users and their devices by Name';
                        obj.common.icon='icons/users.svg';
                        break;
                    default :
                        obj.common.name = adapter.getDescByPeer(key);
                        if (path.split('.').includes('peers')) obj.common.icon='icons/peer.svg';
                        if (path.split('.').includes('users')) obj.common.icon='icons/user.svg';
                }
                obj.common.write= true;
                adapter.createOrExtendObject( `${path}.${key}`, obj, null );
                adapter.extractTreeItems(`${path}.${key}`, value);
            } else {
                adapter.createOrExtendObject(`${path}.${key}`, obj, finalValue);
            }
        }
    }

    /**
     * gets all already known interfaces from the device tree and sets their online state to false
     *
     *
     * @returns {object} a list of all devices / interfaces in the device tree with full Id-path
     */
    async getKnownInterfaces(){
        return new Promise(resolve => {
            adapter.getDevices((err, devices)=>{
                if (!err){
                    const result = {};
                    // adapter.log.debug(`getKnownInterfaces: devices=${JSON.stringify(devices)}; length: ${devices.length}`);
                    for (let n=0; n < devices.length; n++) {
                        result[ devices[n]._id.split('.').pop() ]={};
                        result[ devices[n]._id.split('.').pop() ].id = devices[n]._id;
                        result[ devices[n]._id.split('.').pop() ].online = false;
                    }
                    resolve(result);
                }
            });
        });
    }


    /**
     * sets the online state of all known interfaces of the specified host to false aka offline
     *
     * @param host {string} name of the host
     */
    async setAllKnownInterfacesOffline(host){
        for (const key in adapter._knownInterfaces){
            if (key.split('-')[0] === host) adapter._knownInterfaces[key].online = false;
        }
    }

    /**
     * sets the online state of all known interfaces in the device tree
     */
    setAllKnownInterfacesOnlineState(){
        adapter.log.debug(`setAllKnownInterfacesOnlineState: _knownInterfaces: ${JSON.stringify(adapter._knownInterfaces)}`);
        //for (const key in adapter._knownInterfaces) adapter.setState(`${adapter._knownInterfaces[key].id}.online`, adapter._knownInterfaces[key].online, true);
        for (const key in adapter._knownInterfaces){
            const onlineState = {
                type: 'state',
                common: {
                    name: `Online state of Interface ${key.split('-').pop()} on host ${key.split('-')[0]}`,
                    // 'icon':''
                    'read' : true,
                    'write': false,
                    'role' : 'indicator.connected',
                    'type' : 'boolean'
                }
            };
            adapter.createOrExtendObject(`${adapter._knownInterfaces[key].id}.online`, onlineState, adapter._knownInterfaces[key].online);
        }
    }

    /**
     * Assign the data to the right host inside the device tree
     *
     * @param {string} host Name of the current host
     * @param {object} wgData the given and already parsed WireGuard JSON data
     * @returns {Promise<unknown>}
     */
    async updateDevicetree(host, wgData) {
        // set all knownInterfaces to offline
        await adapter.setAllKnownInterfacesOffline(host);
        return new Promise(function(resolve, reject) {
            try{
                // device tree structure
                // hostname-interface  (device)
                //  +-- interface name (state) - wg0
                //  +-- publicKey      (state)
                //  +-- listenPort     (state)
                //  +-- online         (state)
                //  +-- peers          (group)
                // +---------
                // |   +-- ID          (channel) (take public key as ID)
                // |      +-- name            (state) symbolic name of peer - to be edited by user; always created as an empty string and never updated
                // |      +-- connected       (state)
                // |      +-- endpoint        (state)
                // |      +-- latestHandshake (state)
                // |      +-- transferRx      (state)
                // |      +-- transferTx      (state)
                // |         +-- allowedIPs   (state)
                // |            +-- 0..n      (state)
                // +--------- repeat per peer
                adapter.log.debug(`Host: ${host} has ${ Object.keys(wgData).length } wireguard interface(s).`);
                if ( 0 === Object.keys(wgData).length ){
                    adapter.log.warn(`No info returned from wg executable for host ${host}. Maybe your WireGuard server is down or the monitoring user is missing permissions!`);
                    resolve('');
                } else {
                    // loop through wg interfaces of current host
                    for (let n=0; n < Object.keys(wgData).length; n++){
                        if (!adapter._knownInterfaces[ `${host}-${Object.keys(wgData)[n]}` ]){
                            adapter._knownInterfaces[ `${host}-${Object.keys(wgData)[n]}` ] = {};
                        }
                        adapter._knownInterfaces[ `${host}-${Object.keys(wgData)[n]}` ].online = true;
                        const obj = {
                            type: 'device',
                            common: {
                                name : `Interface ${Object.keys(wgData)[n]} on host ${host}`,
                                icon : 'icons/network-interface-card.svg',
                                // 'icon':'',
                                'read': true,
                                'write': false,
                                'type': 'string'
                            }
                        };
                        const restorePeers = {
                            type: 'state',
                            common: {
                                name: `Restore all suspended peers.`,
                                // 'icon':'',
                                'read': true,
                                'write': true,
                                'type': 'boolean',
                                'role':'button'
                            }
                        };
                        const baseId = `${host}-${ Object.keys(wgData)[n]}`;
                        adapter.log.debug(`baseId: ${baseId}`);
                        adapter.createOrExtendObject( baseId, obj, '' );
                        adapter.createOrExtendObject( baseId+'.restore_all_Peers', restorePeers, true );
                        adapter.subscribeStates(baseId+'.restore_all_Peers');
                        adapter.setAllKnownInterfacesOnlineState();
                        // loop through children of interface
                        adapter.extractTreeItems(baseId, wgData[Object.keys(wgData)[n]]);
                    }
                }
            } catch(error){
                reject(error);
            }
        });
    }


}

if (require.main !== module) {
    // Export the constructor in compact mode
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new Wireguard(options);
} else {
    // otherwise start the instance directly
    new Wireguard();
}