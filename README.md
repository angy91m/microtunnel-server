# microtunnel-server

**microtunnel-server** is an [express](https://www.npmjs.com/package/express) based library to enable post-quantum protected communication between apps (it must be used with [microtunnel-client](https://www.npmjs.com/package/microtunnel-client)). You can send any JSON-serializable data. It also uses [supersphincs](https://www.npmjs.com/package/supersphincs) for app authentication, [kyber-crystals](https://www.npmjs.com/package/kyber-crystals) for asymmetric encryption and [symcryptor](https://www.npmjs.com/package/symcryptor) for symmetric encryption.

## Installation

```bash
npm i microtunnel-server
```

## Usage

First, you have to create app credentials and save them in a json file. Enter in module path typing `cd path-to-your-project/node-modules/microtunnel-server` and then run `npm run -s cred-generate > ../../appCred.json` to save the credentials in your project root.

```javascript
// appCred.json
{
    // Supersphincs keys base-64 encoded
    "publicKey": "X67kzs9zrKfbayvF5SIsulZzfUYHeTm6BoFTD/BWiryIcOWcaR8d6M4LpaOylCi4DqY59ABNt1nNnfFZjG4akE4hcKaMyx5ar9Uds2Op687uecLGWb0n6W+voSDKzMS8",
    "privateKey": "A7sP+3n8KCPgXw7VjziPHZHyDL3eavr6iRn1ampyONlfruTOz3Osp9trK8XlIiy6VnN9Rgd5OboGgVMP8FaKvKggCD7A59Lp4M3LaA9XQi8P+SppMxTmapwjfKVJMacSA0fQnqLZ2m/MP3/YcnyG1TH+RFyEM4O/fE7kxB1/fF+IcOWcaR8d6M4LpaOylCi4DqY59ABNt1nNnfFZjG4akE4hcKaMyx5ar9Uds2Op687uecLGWb0n6W+voSDKzMS8",

    // Random bytes base-64 encoded for ID
    "agent": "285gWsTqj3Gza+3AxJn1qrWzAvf/Lf5i"
}
```

Then you have to create a JSON file containing clients info. In this example we have two apps named `frontEnd` and `sessions`:

```javascript
// authClients.json
{
    "frontEnd": {
        // Client IP
        "ip": "127.0.0.1",

        // The Agent ID of the App
        "agent": "TvjXC2wCNbDS/+sURWP1Oi1lsTKW3ZqT",

        // Supersphincs public key of the client base-64 encoded
        "publicKey": "VvYTfCAhiEDW3abLLhO2ane27HMivnNSLjfKxd4jnOiGCOW0UEXjjacgoZrn/BPvNv+bmerLr0HB+71X2+Eh5NXH2JO6kAoM+SCQblUk3gDyqRbVbYkg/RSCl/6oe0wY"
    },
    "sessions": {
        // Client IP
        "ip": "192.168.0.3",

        // The Agent ID of the App
        "agent": "vwoA1JzkT6d7SXjIBoZ2egYlSn6Ajzge",

        // Supersphincs public key of the client base-64 encoded
        "publicKey": "rPyoqSZrNNUVpjKdhGLDD4sjXd8lgIgnRBY2NP5n8PDDLSvoLoD5n4GjaxbAfSDjagBjN8zztUQTNG1EKO9IgpgTLkfkTkhWqdgkC/K3EQLh6AMCZ8snlnles2QrbHAy"
    }
}
```

Then you can require the module and load it in your express app:

```javascript
const express = require( 'express' );
const app = express();
require( 'microtunnel-server' )( app,
    {
        appCredFile: 'appCred.json',
        authClientsFile: 'authClients.json'
    }
);

// This is a standard express GET route
app.get( '/page/:id', ( req, res ) => {
    const pageId = req.params.id;
    res.json( `Received pageId: ${pageId} via public route` );
} );

// This is an authenticated express GET route for every client in authClients.json
app.authGet( true, '/page/:id', ( req, res ) => {
    const pageId = req.params.id;
    res.json( `Received pageId: ${pageId} via autheticated route from ${req.tunnelClt.name}` );
} );

// This is an authenticated express POST route limited to 'frontEnd' client in authClients.json
app.authPost( 'frontEnd', '/another-route', ( req, res ) => {
    const data = req.body;
    res.json( { receivedData: data } );
} )

app.listen( 3000, '0.0.0.0' );
```

## Configuration

### `require( 'microtunnel-server' )( app, options )`

#### Paramaters

* `app` Required - An Express app/router instance
* `options` Optional - An object containing custom configuration:
  * `api` Optional - Root path for microtunnel (note: must be the same for clients) - Default `'/microtunnel'`
  * `resetMinutes` Optional - Max duration for any session in minutes - Default `15`
  * `appCredFile` Optional - Relative path of the credentials file - Default: enviroment var `APP_CRED`
  * `authClientsFile` Optional - Relative path of the autherized clients file - Default: enviroment var `AUTH_CLTS`

## Methods

### `app.authGet`
```javascript
app.authGet( clientName: String | Array | true, route: String, callback: Function [, ...callback: Function] )
```

#### Parameters
* `clientName` Required - To grant access to route only for authorized clients you can set it as a string containing client name or as an array of these. Otherwise you can authorize every clients setting it to `true`
* `route` Required - The path for which the middleware function is invoked in Express-style
* `callback` Required - Callback functions that accept `req`, `res` and `next`

### `app.authPost`
```javascript
app.authPost( clientName: String | Array | true, route: String, callback: Function [, ...callback: Function] )
```

#### Parameters
* `clientName` Required - To grant access to route only for authorized clients you can set it as a string containing client name or as an array of these. Otherwise you can authorize every clients setting it to `true`
* `route` Required - The path for which the middleware function is invoked in Express-style
* `callback` Required - Callback functions that accept `req`, `res` and `next`

## Note
* Request body will always be decrypted for POST method
* You can call `req.tunnelClt` to show current client properties
* Both `res.send` and `res.json` will decrypt data sent to clients but `microtunnel-client` auto-parses from JSON so use `res.json`
* Since every communication is encrypted you can call `res.json` once for each request
* `app.use` will not affect microtunnel routes
* The POST routes `/microtunnel/auth1` and `/microtunnel/auth2` are reserved (these change will change if you changed default root microtunnel path)