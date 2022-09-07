'use strict';

/*
 * Created with @iobroker/create-adapter v2.0.2
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');

// Load your modules here, e.g.:
const {Client}   = require('ssh2');
const knownPeers = [];
const timeOuts   = [];
let adapter      = null;
let secret       = '';



async function execCommand(hostaddress, user, pass, command){
    return new Promise((resolve, reject) => {
        adapter.log.debug(`Executing command [${command}] on host ${hostaddress}.`);
        const conn = new Client();
        conn.on('ready', () => {
            adapter.log.debug('ssh client :: authenticated');
            adapter.log.debug(`Executing command: [${command}]`);
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
        conn.on('error', function (error) {
            adapter.log.debug('ssh client :: An error occurred: ' + error);
            reject(error);
        });
        conn.connect({
            host: hostaddress,
            port: 22,
            username: adapter.decrypt(secret, user),
            password: adapter.decrypt(secret, pass)
        });
    });
}


/**
 * Opens an ssh connection to the given host, executes the wg-json command and returns the output data of that command.
 *
 * @param {string} hostname symbolic name of the host
 * @param {string} hostaddress IP address of the host
 * @param {string} user username which is used to connect to the host
 * @param {string} pass password for the user
 * @param {boolean} sudo indicator whether sudo should be used
 * @param {boolean} docker indicator whether sudo should be used
 * @returns {Promise<JSON|string>} returns a json structure when successful or an error message
 */
async function getWireguardInfos(hostname, hostaddress, user, pass, sudo, docker) {
    adapter.log.debug(`Retrieving WireGuard status of host [${hostname}] on address [${hostaddress}]`);
    let command = docker ? 'docker exec -it wireguard /usr/bin/wg show all dump' : 'wg show all dump';
    command = sudo ? 'sudo ' + command : command;
    return new Promise(function(resolve, reject) {
        execCommand(hostaddress, user, pass, command)
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
 * @returns {string|*}
 */
function getExtendedCommand(command, hostaddress){
    for (let i=0; i < adapter.config.hosts.length; i++){
        if (adapter.config.hosts[i].hostaddress === hostaddress){
            command = adapter.config.hosts[i].docker? 'docker exec -it wireguard /usr/bin/'+command : command;
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
 * @param user {string}
 * @param pass {string}
 * @param iFace {string}
 * @param peer {string}
 * @returns {Promise<unknown>}
 */
function suspendPeer(hostaddress, path, user, pass, iFace, peer){
    adapter.log.info(`Suspending peer [${peer}] of interface ${iFace} on host ${hostaddress}.`);
    // adapter.log.info(`knownPeers [${knownPeers}].`);
    return new Promise(function(resolve, reject) {
        const command = getExtendedCommand(`wg set ${iFace} peer ${peer} remove`, hostaddress);
        execCommand(hostaddress, user, pass, command)
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
 * @param path {string}
 * @param user {string}
 * @param pass {string}
 * @param iFace {string}
 * @param peer {string}
 * @param ip {string}
 * @returns {Promise<unknown>}
 */
function restorePeer(hostaddress, path, user, pass, iFace, peer, ip){
    adapter.log.info(`Restoring peer [${peer}] of interface ${iFace} on host ${hostaddress} with IP [${ip}].`);
    return new Promise(function(resolve, reject) {
        const command = getExtendedCommand(`wg set ${iFace} peer ${peer} allowed-ips ${ip}`, hostaddress);
        execCommand(hostaddress, user, pass, command)
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
 * @param user {string}
 * @param pass {string}
 * @param iFace {string}
 * @param configFile {string}
 * @returns {Promise<void>}
 */
async function restoreAllPeers(hostaddress, user, pass, iFace, configFile){
    const command = getExtendedCommand(`wg syncconf ${iFace} ${configFile}`, hostaddress);
    execCommand(hostaddress, user, pass, command)
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
async function parseWireguardInfosToJson(wgRawData){
    const data = wgRawData.split('\n');
    adapter.log.debug(`RawData has ${data.length} lines`);
    for (let n = 0; n < data.length; n++) {
        data[n] = data[n].split('\t');
    }
    adapter.log.debug(`Workdata: ${JSON.stringify(data)}`);
    // first row holds server data; rest are peers; last one is empty
    const wg = {};
    for ( let i=0; i<data.length; i++ ) {
        if ( i===0 || (data[i][0] !== data[i-1][0]) ){
            if (data[i][0] === '') break;
            adapter.log.silly(`New Interface: ${data[i][0]}. Initialize object.`);
            wg[data[i][0]]= {};
            // wg[data[i][0]].privateKey = data[i][1]; // don't show the private key in ioBroker
            wg[data[i][0]].publicKey= data[i][2];
            wg[data[i][0]].listenPort = data[i][3];
            wg[data[i][0]].fwmark = data[i][4];
            wg[data[i][0]].peers = {};
        }else{
            // interface public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
            adapter.log.silly(`New Peer ${data[i][1]} for interface ${ data[i][0] }`);
            wg[data[i][0]].peers[data[i][1]] = {};
            wg[data[i][0]].peers[data[i][1]].presharedKey = data[i][2];
            wg[data[i][0]].peers[data[i][1]].endpoint = data[i][3];
            wg[data[i][0]].peers[data[i][1]].allowedIps = data[i][4].split(',');
            wg[data[i][0]].peers[data[i][1]].latestHandshake = data[i][5];
            wg[data[i][0]].peers[data[i][1]].transferRx = data[i][6];
            wg[data[i][0]].peers[data[i][1]].transferTx = data[i][7];
            wg[data[i][0]].peers[data[i][1]].persistentKeepalive = data[i][8];
        }
    }
    return(wg);
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
function createOrExtendObject(id, objData, value) {
    adapter.getObject(id, function (err, oldObj) {
        if (!err && oldObj) {
            if ( objData.name === oldObj.common.name ){
                adapter.setState(id, value, true);
            } else{
                adapter.extendObject(id, objData, () => {adapter.setState(id, value, true);});
            }
        } else {
            adapter.setObjectNotExists(id, objData, () => {adapter.setState(id, value, true);});
        }
    });
}


/**
 * sets the connected state of a peer and also creates the syspend_Peer button and the isSuspended indicator
 *
 * @param {string} path path to the peer in object tree
 * @param {boolean} value value to set
 */
function setConnectedState(path, value) {
    createOrExtendObject(`${path}.suspend_Peer`, {
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
    createOrExtendObject(`${path}.restore_Peer`, {
        type: 'state',
        common: {
            name: `Bring that temporarily suspended peer back to action.`,
            // 'icon':''
            'read': false,
            'write': true,
            'type': 'boolean',
            'role':'button'
        }
    }, true);
    adapter.subscribeStates(`${path}.restore_Peer`);
    createOrExtendObject(`${path}.connected`, {
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
    createOrExtendObject(`${path}.isSuspended`, {
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
function extractTreeItems(path, obj ){
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
            case 'listenPort': obj.common.role='info.port';
                break;
            case 'latestHandshake':{
                obj.common.role='date';
                obj.common.type='number';
                finalValue = Number(value*1000); // convert unix time to utc
                if ( (new Date()-new Date(value*1000)) > 130000){
                    setConnectedState(path, false);
                } else {
                    obj.common.role='date.end';
                    setConnectedState(path, true);
                }
            }
        }
        // If there is an object inside the given structure, dive one level deeper
        if (typeof value === 'object'){
            // It's an object - so iterate deeper
            // adapter.log.debug(`Deeper Object: name ${key} | value ${JSON.stringify(value)}`);
            let groupname = key;
            // assign group name translation if given on config page
            for (let n=0; n < adapter.config.names.length; n++){
                if ( key === adapter.config.names[n].pubKey ){
                    groupname = adapter.config.names[n].groupname;
                    knownPeers.push(key);
                    break;
                }
            }
            obj.type= 'group';
            obj.common.name = groupname;
            obj.common.write= true;
            createOrExtendObject( `${path}.${key}`, obj, null );
            extractTreeItems(`${path}.${key}`, value);
        } else {
            createOrExtendObject(`${path}.${key}`, obj, finalValue);
        }
    }
}


/**
 * Assign the data to the right host inside the device tree
 *
 * @param {string} host Name of the current host
 * @param {object} wgData the given and already parsed WireGuard JSON data
 * @returns {Promise<unknown>}
 */
async function updateDevicetree(host, wgData) {
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
            const knownInterfaces = [];
            if (Object.keys(wgData).length === 0){
                adapter.log.error(`No info returned from wg executable. Maybe your WireGuard server is down or monitoring user is missing permissions!`);
                adapter.setState('info.connection', false, true);
            } else {
                adapter.setState('info.connection', true, true);
                // loop through wg interfaces of current host
                for (let n=0; n < Object.keys(wgData).length; n++){
                    const obj = {
                        type: 'device',
                        common: {
                            name: `Interface ${Object.keys(wgData)[n]} on host ${host}`,
                            // 'icon':''
                            'read': true,
                            'write': false,
                            'type': 'string'
                        }
                    };
                    const onlineState = {
                        type: 'state',
                        common: {
                            name: `Interface is online`,
                            // 'icon':''
                            'read': true,
                            'write': false,
                            'type': 'boolean',
                            'role':'indicator.reachable'
                        }
                    };
                    const restorePeers = {
                        type: 'state',
                        common: {
                            name: `Restore all suspended peers.`,
                            // 'icon':''
                            'read': true,
                            'write': true,
                            'type': 'boolean',
                            'role':'button'
                        }
                    };
                    const baseId = `${host}-${ Object.keys(wgData)[n]}`;
                    knownInterfaces.push(baseId);
                    createOrExtendObject( baseId, obj, '' );
                    createOrExtendObject( baseId+'.restore_all_Peers', restorePeers, true );
                    adapter.subscribeStates(baseId+'.restore_all_Peers');
                    // loop through children of interface
                    extractTreeItems(baseId, wgData[Object.keys(wgData)[n]]);
                    if (n === Object.keys(wgData).length-1){
                        // adapter.log.debug(`Going to set online states of interfaces.`);
                        // set online state of every interface
                        adapter.getDevices((err, devices)=>{
                            for (let i=0; i < devices.length; i++) {
                                if (knownInterfaces.includes(devices[i]._id.split('.').pop())) {
                                    createOrExtendObject(`${devices[i]._id}.online`, onlineState, true);
                                } else {
                                    createOrExtendObject(`${devices[i]._id}.online`, onlineState, false);
                                }
                            }
                        });
                    }
                }
            }
        } catch(error){
            reject(error);
        }
    });
}


class Wireguard extends utils.Adapter {

    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: 'wireguard',
        });
        this.on('ready', this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        // this.on('objectChange', this.onObjectChange.bind(this));
        // this.on('message', this.onMessage.bind(this));
        this.on('unload', this.onUnload.bind(this));
    }

    async onStateChange(id, state){
        if (state) {
            // The state was changed
            // this.log.info(`state ${id} changed: ${state.val} (ack = ${state.ack})`);
            if (!state.ack) {
                // manual change / request
                // wireguard.0.ganymed-wg0.peers.kBTx8Hyd6V51XSzI2fhzR0Wngfhwg3cAJNBvSevCi3Q=.suspend_Peer
                let hostaddress = '';
                let user        = '';
                let pass        = '';
                let configFile  = '';
                const path = id.split('.', 5).join('.');
                const iFace = id.split('.', 3).pop().split('-').pop();
                const peer = id.split('.', 5).pop();
                const searchHost = id.split('.', 3).pop().split('-', 1).pop();
                for (let host=0; host < this.config.hosts.length; host++) {
                    if (this.config.hosts[host].name === searchHost) {
                        hostaddress = this.config.hosts[host].hostaddress;
                        user = this.config.hosts[host].user;
                        pass = this.config.hosts[host].password;
                        break;
                    }
                }
                if ('suspend_Peer' === id.split('.').pop()){
                    adapter.log.info(`Suspending peer on interface ${iFace}`);
                    await suspendPeer(hostaddress, path, user, pass, iFace, peer);
                } else if ('restore_Peer' === id.split('.').pop()){
                    adapter.log.info(`Path: ${path+'.allowedIps.0'}`);
                    adapter.getState(path+'.allowedIps.0', function (err, state){
                        if (!err && state) {
                            adapter.log.info(`Restoring peer ${peer} with IP ${state.val} on interface ${iFace}.`);
                            restorePeer(hostaddress, id.split('.', 5).join('.'), user, pass, iFace, peer, state.val);
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
                    await restoreAllPeers(hostaddress, user, pass, iFace, configFile);
                }
            }
        }
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Reset the connection indicator during startup
        this.setState('info.connection', false, true);
        // Initialize your adapter here
        adapter = this; // preserve adapter reference to address functions etc. correctly later
        const settings = this.config;
        this.getForeignObject('system.config', (err, obj) => {
            if (obj && obj.native && obj.native.secret) {
                secret = obj.native.secret;
            } else {
                throw new Error('Unable to decrypt config data.');
            }
        });
        if (settings.hosts.length === 1){
            this.log.info(`There is ${settings.hosts.length} wireguard host to monitor.`);
        } else {
            this.log.info(`There are ${settings.hosts.length} wireguard hosts to monitor.`);
        }
        try{
            for (let host=0; host < settings.hosts.length; host++) {
                timeOuts.push(setInterval(async function pollHost() {
                    await getWireguardInfos(settings.hosts[host].name, settings.hosts[host].hostaddress, settings.hosts[host].user, settings.hosts[host].password, settings.hosts[host].sudo, settings.hosts[host].docker)
                        .then(async (wgInfos)=> {
                            await parseWireguardInfosToJson(wgInfos)
                                .then(async (wgJson)=>{
                                    await updateDevicetree(settings.hosts[host].name, wgJson);
                                })
                                .catch((error)=>{
                                    adapter.log.warn(`Data from host [${settings.hosts[host].name}] can't be parsed. Please check and fix. =>[${error}]`);
                                });
                        })
                        .catch((error) => {
                            adapter.log.warn(`Connection to host [${settings.hosts[host].name}] can't be established. Please check and fix. =>[${error}]`);
                        });
                }, 1000 * settings.hosts[host].pollInterval));
            }
            for (let n=0; n < timeOuts.length; n++){
                this.log.info(`Started ${settings.hosts[n].pollInterval} seconds monitoring interval for host [${settings.hosts[n].name}]`);
            }
        } catch(error)  {
            this.log.error(error);
            this.setState('info.connection', false, true);
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