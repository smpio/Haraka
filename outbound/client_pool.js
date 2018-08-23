"use strict";

const generic_pool = require('generic-pool');
const utils        = require('haraka-utils');

const sock         = require('../line_socket');
const server       = require('../server');
const logger       = require('../logger');

const cfg          = require('./config');

const tls       = require('tls');

const SocksClient = require('socks').SocksClient;

const log       = require('../logger');

const pluggableStream = require('../tls_socket').pluggableStream


function setup_line_processor (socket) {
    let current_data = '';
    socket.process_data = function (data) {
        current_data += data;
        let results;
        while ((results = utils.line_regexp.exec(current_data))) {
            const this_line = results[1];
            current_data = current_data.slice(this_line.length);
            socket.emit('line', this_line);
        }
    };

    socket.process_end = function () {
        if (current_data.length) {
            socket.emit('line', current_data);
        }
        current_data = '';
    };

    socket.on('data', function (data) { socket.process_data(data);});
    socket.on('end',  function ()     { socket.process_end();     });
}

const certsByHost = {};
const ctxByHost = {};

function pipe (cleartext, socket) {
    cleartext.socket = socket;

    function onError (e) {
    }

    function onClose () {
        socket.removeListener('error', onError);
        socket.removeListener('close', onClose);
    }

    socket.on('error', onError);
    socket.on('close', onClose);
}

function _create_socket (pool_name, port, host, local_addr, is_unix_socket, callback, proxy) {

    if(proxy){
        if(proxy.proxy.ipaddress === host){
            host = '127.0.0.1';
            proxy = undefined;
        }
    }
    if(!proxy || is_unix_socket){
        var socket = is_unix_socket ? sock.connect({path: host}) :
            sock.connect({port: port, host: host, localAddress: local_addr});
        socket.__pool_name = pool_name;
        socket.__uuid = utils.uuid();
        socket.setTimeout(cfg.connect_timeout * 2000);
        logger.logdebug(
            '[outbound] created',
            {
                uuid: socket.__uuid,
                host: host,
                port: port,
                pool_timeout: cfg.pool_timeout
            }
        );
        socket.once('connect', function () {
            socket.removeAllListeners('error'); // these get added after callback
            socket.removeAllListeners('timeout');
            callback(null, socket);
        });
        socket.once('error', function (err) {
            socket.end();
            callback(`Outbound connection error: ${err}`, null);
        });
        socket.once('timeout', function () {
            socket.end();
            callback(`Outbound connection timed out to ${host}:${port}`, null);
        });
    }else{
        let proxy_options = Object.assign({}, proxy);
        proxy_options.destination = {
            host: host,
            port: port
        };
        proxy_options.command = 'connect';
        SocksClient.createConnection(proxy_options, (err, info) => {
            if (err) {
                return callback(err, null);
            }
            var cryptoSocket = new pluggableStream(info.socket);
            setup_line_processor(cryptoSocket);
            const socket = cryptoSocket;
            socket.upgrade = (options, cb2) => {

                options = Object.assign(options, certsByHost['*']);
                options.socket = info.socket;

                var cleartext = new tls.connect(options);
                pipe(cleartext, cryptoSocket);

                cleartext.on('error', err => {
                    if (err.reason) {
                    log.logerror("client TLS error: " + err);
                }
            })
            cleartext.getPeerCertificate();
            cleartext.getCipher();


            socket.cleartext = cleartext;

            if (socket._timeout) {
                cleartext.setTimeout(socket._timeout);
            }

            cleartext.setKeepAlive(socket._keepalive);
            setup_line_processor(socket.cleartext);
            socket.attach(socket.cleartext);

            log.logdebug('client TLS upgrade in progress, awaiting secured.');

        }
        socket.__pool_name = pool_name;
        socket.__uuid = utils.uuid();
        socket.setTimeout(cfg.connect_timeout * 3000);
        logger.logdebug(
            '[outbound] created',
            {
                uuid: socket.__uuid,
                host: host,
                port: port,
                pool_timeout: cfg.pool_timeout
            }
        );
        socket.removeAllListeners('error'); // these get added after callback
        socket.removeAllListeners('timeout');
        callback(null, socket);
    });


    }
}


// Separate pools are kept for each set of server attributes.
function get_pool (port, host, local_addr, is_unix_socket, max, proxy) {
    port = port || 25;
    host = host || 'localhost';

    var proxy_ip = '';
    if(proxy && proxy.proxy){
        proxy_ip = proxy.proxy.ipaddress;
    }else{
        proxy = undefined
    }

    const name = `outbound::${port}:${host}:${local_addr}:${cfg.pool_timeout}:${proxy_ip}`;
    if (!server.notes.pool) {
        server.notes.pool = {};
    }
    if (!server.notes.pool[name]) {
        const pool = generic_pool.Pool({
            name: name,
            create: function (done) {
                _create_socket(this.name, port, host, local_addr, is_unix_socket, done, proxy);
            },
            validate: function (socket) {
                return socket.__fromPool && socket.writable;
            },
            destroy: function (socket) {
                logger.logdebug(`[outbound] destroying pool entry ${socket.__uuid} for ${host}:${port}`);
                socket.removeAllListeners();
                socket.__fromPool = false;
                socket.on('line', function (line) {
                    // Just assume this is a valid response
                    logger.logprotocol(`[outbound] S: ${line}`);
                });
                socket.once('error', function (err) {
                    logger.logwarn(`[outbound] Socket got an error while shutting down: ${err}`);
                });
                socket.once('end', function () {
                    logger.loginfo("[outbound] Remote end half closed during destroy()");
                    socket.destroy();
                })
                if (socket.writable) {
                    logger.logprotocol("[outbound] C: QUIT");
                    socket.write("QUIT\r\n");
                }
                socket.end(); // half close
            },
            max: max || 10,
            idleTimeoutMillis: cfg.pool_timeout * 1000,
            log: function (str, level) {
                if (/this._availableObjects.length=/.test(str)) return;
                level = (level === 'verbose') ? 'debug' : level;
                logger[`log${level}`](`[outbound] [${name}] ${str}`);
            }
        });
        server.notes.pool[name] = pool;
    }
    return server.notes.pool[name];
}

// Get a socket for the given attributes.
exports.get_client = function (port, host, local_addr, is_unix_socket, callback, proxy) {
    if (cfg.pool_concurrency_max == 0) {
        return _create_socket(null, port, host, local_addr, is_unix_socket, callback, proxy);
    }

    const pool = get_pool(port, host, local_addr, is_unix_socket, cfg.pool_concurrency_max, proxy);
    if (pool.waitingClientsCount() >= cfg.pool_concurrency_max) {
        return callback("Too many waiting clients for pool", null);
    }
    pool.acquire(function (err, socket) {
        if (err) return callback(err);
        socket.__acquired = true;
        logger.loginfo(`[outbound] acquired socket ${socket.__uuid} for ${socket.__pool_name}`);
        callback(null, socket);
    });
}

exports.release_client = function (socket, port, host, local_addr, error) {
    logger.logdebug(`[outbound] release_client: ${socket.__uuid} ${host}:${port} to ${local_addr}`);

    const name = socket.__pool_name;

    if (!name && cfg.pool_concurrency_max == 0) {
        return sockend();
    }

    if (!socket.__acquired) {
        logger.logwarn(`Release an un-acquired socket. Stack: ${(new Error()).stack}`);
        return;
    }
    socket.__acquired = false;

    if (!(server.notes && server.notes.pool)) {
        logger.logcrit(`[outbound] Releasing a pool (${name}) that doesn't exist!`);
        return;
    }
    const pool = server.notes.pool[name];
    if (!pool) {
        logger.logcrit(`[outbound] Releasing a pool (${name}) that doesn't exist!`);
        return;
    }

    if (error) {
        return sockend();
    }

    if (cfg.pool_timeout == 0) {
        logger.loginfo("[outbound] Pool_timeout is zero - shutting it down");
        return sockend();
    }

    socket.removeAllListeners('close');
    socket.removeAllListeners('error');
    socket.removeAllListeners('end');
    socket.removeAllListeners('timeout');
    socket.removeAllListeners('line');

    socket.__fromPool = true;

    socket.once('error', function (err) {
        logger.logwarn(`[outbound] Socket [${name}] in pool got an error: ${err}`);
        sockend();
    });

    socket.once('end', function () {
        logger.loginfo(`[outbound] Socket [${name}] in pool got FIN`);
        socket.writable = false;
        sockend();
    });

    pool.release(socket);

    function sockend () {
        socket.__fromPool = false;
        if (server.notes.pool && server.notes.pool[name]) {
            server.notes.pool[name].destroy(socket);
        } else {
            socket.removeAllListeners();
            socket.destroy();
        }
    }
}

exports.drain_pools = function () {
    if (!server.notes.pool || Object.keys(server.notes.pool).length == 0) {
        return logger.logdebug("[outbound] Drain pools: No pools available");
    }
    Object.keys(server.notes.pool).forEach(function (p) {
        logger.logdebug(`[outbound] Drain pools: Draining SMTP connection pool ${p}`);
        server.notes.pool[p].drain(function () {
            if (!server.notes.pool[p]) return;
            server.notes.pool[p].destroyAllNow();
            delete server.notes.pool[p];
        });
    });
    logger.logdebug("[outbound] Drain pools: Pools shut down");
}
