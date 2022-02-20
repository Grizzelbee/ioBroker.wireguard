'use strict';

/*
 * Created with @iobroker/create-adapter v2.0.2
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');

// Load your modules here, e.g.:
const {Client} = require('ssh2');
const timeOuts=[];
let adapter=null;


/**
 * Opens an ssh connection to the given host, executes the wg-json command and returns the output data of that command.
 *
 * @param {string} hostname symbolic name of the host
 * @param {string} hostaddress IP address of the host
 * @param {string} user username which is used to connect to the host
 * @param {string} pass password for the user
 * @returns {Promise<JSON|string>} returns a json structure when successful or an error message
 */
async function getWireguardInfos(hostname, hostaddress, user, pass) {
    adapter.log.info(`Connecting to host [${hostname}] on address [${hostaddress}]`);
    return new Promise(function(resolve, reject) {
        const conn = new Client();
        conn.on('ready', () => {
            adapter.log.debug('ssh client :: ready');
            conn.exec('wg-json\n', {},(error, responseStream) => {
                if (error) reject( error );
                let jsonData = '';
                responseStream.on('close', () => {
                    adapter.log.debug('Stream :: close');
                    conn.end();
                    adapter.log.debug(`jsonData (unparsed): ${jsonData}`);
                    resolve(jsonData);
                })
                    .on('data', (data) => {
                        // collect and assemble all data from stream
                        jsonData += data;
                    });
            });
        }).connect({
            host: hostaddress,
            port: 22,
            username: user,
            password: pass
        });
    });
}


/**
 *  Takes the result of wg-json and tries to parse it into a JSON object
 *
 * @param {string} wgInfos The unparsed data from the command line
 * @returns {Promise<unknown>} Returns a JSON object on success, or an error message in case of a failure
 */
async function parseWireguardInfos(wgInfos) {
    return new Promise(function(resolve, reject) {
        try{
            const payload = JSON.parse(wgInfos);
            resolve(payload);
        } catch(error){
            reject(error);
        }
    });
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
 * Navigates through the given object and build the device tree out of it.
 *
 * @param {string} path path inside the ioBroker object tree
 * @param {object} obj the object to handle
 */
function extractTreeItems(path, obj ){
    let finalValue;
    // build key-value pairs from object structure
    for (const [key, value] of Object.entries(obj) ) {
        adapter.log.debug(`Key ${key}: Value ${value} | typeof value ${ typeof value}`);
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
                obj.common.role='value';
                break;
            }
            case 'endpoint': obj.common.role='info.ip';
                break;
            case 'listenPort': obj.common.role='info.port';
                break;
            case 'connected': {
                obj.common.role='indicator.reachable';
                obj.common.name='Peer is connected';
            }
                break;
            case 'latestHandshake':{
                obj.common.role='date.end';
                finalValue = value*1000; // convert unix time to utc
                if ( (new Date()-finalValue) > 130000){
                    createOrExtendObject(`${path}.connected`, {
                        type: 'state',
                        common: {
                            name: 'Peer is connected',
                            // 'icon':''
                            'read': true,
                            'write': false,
                            'role':'indicator.reachable',
                            'type': 'boolean'
                        }
                    }, false);
                } else {
                    obj.common.role='indicator.reachable';
                    createOrExtendObject(`${path}.connected`, {
                        type: 'state',
                        common: {
                            name: 'Peer is connected',
                            // 'icon':''
                            'read': true,
                            'write': false,
                            'role':'indicator.reachable',
                            'type': 'boolean'
                        }
                    }, true);
                }
            }
        }
        // If there is an object inside the given structure, dive one level deeper
        if (typeof value === 'object'){
            // It's an object - so iterate deeper
            adapter.log.debug(`Deeper Object: name ${key} | value ${JSON.stringify(value)}`);
            let groupname = key;
            // assign group name translation if given on config page
            for (let n=0; n < adapter.config.names.length; n++){
                if ( key === adapter.config.names[n].pubKey ){
                    groupname = adapter.config.names[n].groupname;
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
            if (Object.keys(wgData).length === 0){
                adapter.log.error(`No info returned from wg-json script. Maybe your WireGuard server is down!`);
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
                    const baseId = `${host}-${ Object.keys(wgData)[n]}`;
                    createOrExtendObject( baseId, obj, '' );
                    // loop through children of interface
                    extractTreeItems(baseId, wgData[Object.keys(wgData)[n]]);
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
        // this.on('stateChange', this.onStateChange.bind(this));
        // this.on('objectChange', this.onObjectChange.bind(this));
        // this.on('message', this.onMessage.bind(this));
        this.on('unload', this.onUnload.bind(this));
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
        let secret;
        adapter.getForeignObject('system.config', (err, obj) => {
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
                this.log.debug(JSON.stringify(settings.hosts[host]));
                timeOuts.push(setInterval(async function pollHost() {
                    const wgInfos = await getWireguardInfos(settings.hosts[host].name, settings.hosts[host].hostaddress, adapter.decrypt(secret, settings.hosts[host].user), adapter.decrypt(secret, settings.hosts[host].password));
                    const wgData = await parseWireguardInfos(wgInfos);
                    await updateDevicetree(settings.hosts[host].name, wgData);
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