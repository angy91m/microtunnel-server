"use strict";
const { superSphincs } = require( 'supersphincs' ),
    { kyber } = require( 'kyber-crystals' ),
    symCryptor = require( 'symcryptor' ),
    { encode: cbEncode, decode: cbDecode} = require( 'cbor-x' );

if ( process.argv[1] === __filename && process.argv[2] === 'cred-generate' ) {
    Promise.all( [
        superSphincs.keyPair(),
        symCryptor.rndBytes( 24 )
    ] )
    .then( res => {
        const cred = {
            publicKey: Buffer.from( res[0].publicKey ).toString( 'base64' ),
            privateKey: Buffer.from( res[0].privateKey ).toString( 'base64' ),
            agent: res[1].toString( 'base64' )
        }
        console.log( JSON.stringify( cred, null, 4 ) );
    } )
    .catch( console.error )
    .finally( process.exit );
} else {
    const octetParser = require( 'express' ).raw( {
        inflate: false,
        limit: '1mb',
        type: 'application/octet-stream'
    } );

    const auth1Len = 64;
    const auth2Len = 31554;

    const servAuth = ( app, options = {} ) => {
        const defaultOptions = {
            api: '/microtunnel',
            resetMinutes: 15,
            appCredFile: process.env.APP_CRED,
            authClientsFile: process.env.AUTH_CLTS,
            ...options
        };
        const { api, resetMinutes, appCredFile, authClientsFile } = defaultOptions;
        class AuthServerSex {
            constructor( name, clts ) {
                this.name = name;
                if ( clts.constructor !== Array ) clts = [clts];
                this.clients = clts.map( c => ( {
                    name,
                    ip: c.ip,
                    agent: c.agent,
                    signature: Buffer.from( c.publicKey, 'base64' ),
                    decrypting: 0,
                    state: 0,
                    key: undefined,
                    shaKey: undefined,
                    pendingReset: false,
                    beginDecrypt() {
                        this.decrypting = this.decrypting + 1;
                    },
                    endDecrypt() {
                        this.decrypting = this.decrypting - 1;
                        if ( this.decrypting === 0 && this.pendingReset ) {
                            this.reset();
                        }
                    },
                    delete() {
                        this.state = 0;
                        this.key = undefined;
                        this.shaKey = undefined;
                        this.pendingReset = false;
                    },
                    resetTimer() {
                        clearTimeout( this.timer );
                        this.timer = setTimeout( () => {
                            if ( this.decrypting ) return this.pendingReset = true;
                            this.delete();
                        }, resetMinutes * 60000 );
                    },
                    reset() {
                        this.resetTimer();
                        this.delete();
                    }
                } ) );
            }
        }
    
        class AuthServerSessions extends Array {
            constructor( authClients ) {
                const clients = [];
                for ( const clt in authClients ) {
                    clients.push( new AuthServerSex( clt, authClients[clt] ) );
                }
                super( ...clients );
            }
            get( str ) {
                if ( !str || typeof str !== 'string' ) return false;
                const found = this.find( el => el.name === str );
                if ( found ) return found;
                return false;
            }
            findSrv( ip, agent ) {
                if (
                    ( !ip || typeof ip !== 'string' )
                    || ( !agent || typeof agent !== 'string' )
                ) return false;
                let found = false;
                for ( let i = 0; i < this.length; i++ ) {
                    const clt = this[i].clients.find( c => c.ip === ip && c.agent === agent );
                    if ( clt ) {
                        found = clt;
                        break;
                    }
                }
                if ( found ) return found;
                return false;
            }
        }
        const sendError = function () {
            this.status( 404 );
            this.send();
        };
        const sessions = new AuthServerSessions( require( authClientsFile ) );
        const appCred = require( appCredFile );
        const unless = ( middleware ) => {
            return ( req, res, next ) => {
                if ( req.originalUrl.startsWith( api + '/' ) ) {
                    return next();
                } else {
                    return middleware( req, res, next );
                }
            };
        };
        const origUse = app.use;
        app.use = function ( ...callbacks ) {
            if ( !callbacks.length ) throw new Error( '.use() method requires at least one function' );
            if ( typeof callbacks[0] ==='string' || callbacks[0].constructor === RegExp || callbacks[0].constructor === Array ) {
                if ( !( callbacks.length -1 ) ) throw new Error( '.use() method requires at least one function' );
                const route = callbacks.shift();
                for ( let i = 0; i < callbacks.length; i++ ) {
                    origUse.call( this, route, unless( callbacks[i] ) );
                }
            } else {
                for ( let i = 0; i < callbacks.length; i++ ) {
                    origUse.call( this, unless( callbacks[i] ) );
                }
            }
        };
        app.post( api +'/auth1', octetParser, ( req, res ) => {
            const ip = req.ip;
            const agent = req.get( 'User-Agent' );
            if ( !ip || !agent ) return sendError.call( res );
            const clt = sessions.findSrv( ip, agent );
            if ( !clt ) return sendError.call( res );
            clt.reset();
            if ( parseInt( req.headers['content-length'], 10 ) !== auth1Len ) return sendError.call( res );
            Promise.all( [
                kyber.keyPair(),
                symCryptor.rndBytes( 64 ),
                superSphincs.signDetached( req.body, Buffer.from( appCred.privateKey, 'base64' ), appCred.agent )
            ] )
            .then( result => {
                clt.key = result[0].privateKey;
                clt.shaKey = result[1];
                const ret = Buffer.concat( [result[0].publicKey, Buffer.from( result[2] ), result[1]] );
                clt.state = 1;
                res.set( {
                    'Content-Type': 'application/octet-stream'
                } );
                res.send( ret );
                return res.end();
            } )
            .catch( () => sendError.call( res ) );
        } );

        app.post( api +'/auth2', octetParser, ( req, res ) => {
            const ip = req.ip;
            const agent = req.get( 'User-Agent' );
            if ( !ip || !agent ) return sendError.call( res );
            const clt = sessions.findSrv( ip, agent );
            if ( !clt ) {
                return sendError.call( res );
            } else if ( clt.state !== 1 ) {
                clt.reset();
                return sendError.call( res );
            }
            if ( parseInt( req.headers['content-length'], 10 ) !== auth2Len ) return sendError.call( res );
            const data = new Uint8Array( req.body );
            const ciphertext = data.slice( 0, 1568 ),
                encShaKey = data.slice( 1568, 1616 ),
                encSignedRnd = data.slice( 1616 );
            kyber.decrypt( ciphertext, clt.key )
            .then( async decryptedKey => {
                const shaKey = await symCryptor.decrypt( encShaKey, decryptedKey );
                const signToCheck = new Uint8Array( await symCryptor.decrypt( encSignedRnd, decryptedKey, shaKey, clt.agent ) );
                const verySign = await superSphincs.verifyDetached( signToCheck, clt.shaKey, clt.signature, shaKey );
                if ( !verySign ) throw new Error( 'Internal server error' );
                clt.key = decryptedKey;
                clt.shaKey = shaKey;
                const confirmation = await symCryptor.encrypt(
                    Buffer.from( 'true' ),
                    decryptedKey,
                    shaKey,
                    appCred.agent
                );
                res.send( confirmation );
                clt.state = 2;
                res.set( {
                    'Content-Type': 'application/octet-stream'
                } );
                return res.end();
            } )
            .catch( () => sendError.call( res ) );
        } );

        const clientParser = ( clts, parseBody = false ) => {
            return async ( req, res, next ) => {
                const ip = req.ip;
                const agent = req.get( 'User-Agent' );
                if ( !ip || !agent ) return sendError.call( res );
                let clt;
                for ( let i = 0; i < clts.length; i++ ) {
                    const found = clts[i].clients.find( c => c.ip === ip && c.agent === agent && c.state === 2 );
                    if ( found ) {
                        clt = found;
                        break;
                    }
                }
                if ( !clt ) return sendError.call( res );
                const cltClone = {
                    name: clt.name,
                    ip: clt.ip,
                    agent: clt.agent,
                    signature: clt.signature,
                    state: clt.state,
                    key: Buffer.from( clt.key ),
                    shaKey: Buffer.from( clt.shaKey ),
                    timer: clt.timer,
                    delete() {
                        clt.delete();
                    },
                    resetTimer() {
                        clt.resetTimer();
                    },
                    reset() {
                        clt.reset();
                    }
                };
                req.tunnelClt = cltClone;
                const origSend = res.send;
                res.send = async function ( obj ) {
                    try {
                        const encrypted = await symCryptor.encrypt( cbEncode( obj ), cltClone.key, cltClone.shaKey, appCred.agent );
                        origSend.call( this, encrypted );
                        res.end();
                    } catch {
                        res.status( 400 );
                        res.end();
                    }
                };
                res.json = async ( obj ) => {
                    await res.send( obj );
                }
                res.set( {
                    'Content-Type': 'application/octet-stream'
                } );
                if ( !parseBody ) return next();
                while ( clt.pendingReset ) {
                    await new Promise( r => setTimeout( r, 200 ) );
                }
                clt.beginDecrypt();
                try {
                    const decBody = await symCryptor.decrypt( req.body, cltClone.key, cltClone.shaKey, cltClone.agent );
                    req.body = cbDecode( decBody );
                    next();
                } catch {
                    sendError.call( res );
                } finally {
                    clt.endDecrypt();
                }
            };
        };
        const addAppCltRoute = ( cltNames, method, route = '/', ...callbacks ) => {
            const clts = [];
            if ( typeof cltNames === 'string' ) {
                clts.push( sessions.get( cltNames ) );
            } else if ( cltNames.constructor === Array ) {
                for ( let clt of cltNames ) {
                    if ( !clts.find( el => el.name === clt ) ) clts.push( sessions.get( clt ) );
                }
            } else if ( cltNames === true ) {
                for ( let clt of sessions ) {
                    clts.push( clt );
                }
            }
            if ( !clts.length ) throw new Error( 'Invalid server name' );
            if ( !clts.every( a => a ) ) throw new Error( 'Invalid server name' );
            if ( !callbacks.length ) throw new Error( 'Callbacks argument requires at least one function' );
            if ( method === 'get' ) {
                app.get( api + route, clientParser( clts ), ...callbacks );
            } else if ( method === 'post' ) {
                app.post( api + route, octetParser, clientParser( clts, true ), ...callbacks );
            } else {
                throw new Error( 'Invalid route method' );
            }
        };
        app.authGet = function ( clientName, route, ...callbacks ) {
            addAppCltRoute( clientName, 'get', route, ...callbacks );
        }
        app.authPost = function ( clientName, route, ...callbacks ) {
            addAppCltRoute( clientName, 'post', route, ...callbacks );
        }
    };

    module.exports = servAuth;
}