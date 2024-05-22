# wolfHSM

wolfHSM is a software framework that provides an unified API for HSM operations
such as cryptographic operations, key management, and non-volatile storage.
It is designed to improve portability of code related to HSM applications,
easing the challenge of moving between hardware with enhanced security
features without being tied to any vendor-specific library calls. It
dramatically simplifies client applications by allowing direct use of wolfCrypt
APIs, with the library automatically offloading all sensitive cryptographic
operations to the HSM core as remote procedure calls with no additional logic
required by the client app.

Although initially targeted to automotive-style HSM-enabled microcontrollers,
wolfHSM provides an extensible solution to support future capabilities of
platforms while still supporting standardized interfaces and protocols such as
PKCS11 and AUTOSAR SHE. It has no external dependencies other than wolfCrypt and
is portable to almost any runtime environment.

## Features

- Secure non-volatile object storage with user-based permissions
- Cryptographic key management with support for hardware keys
- Hardware cryptographic support for compatible devices
- Fully asynchronous client API
- Flexible callback architecture enables custom use cases without modifying library
- Use wolfCrypt APIs directly on client, with automatic offload to HSM core
- Image manager to support chain of trust
- Integration with AUTOSAR
- Integration with SHE+
- PKCS11 interface available
- TPM 2.0 interface available
- Secure OnBoard Communication (SecOC) module integration available
- Certificate handling
- Symmetric and Asymmetric keys and cryptography
- Supports "crypto agility" by providing every algorithm implemented in wolfCrypt, not just those implemented by your silicon vendor
- FIPS 140-3 available

## Architecture

wolfHSM employs a client-server architecture where the server runs in a trusted
and secure environment (typically on an secure coprocessor) and the client is a library
that can be linked against user applications. This architecture ensures that
sensitive cryptographic operations and key management are handled securely
 within the server, while the client library abstracts away the lower level
communication with the server.

- Server: The server component of wolfHSM is a standalone application that runs
 on the HSM core. It handles cryptographic operations, key management, and
 non-volatile storage within a secure environment. The server is responsible
 for processing requests from clients and returning the results.

- Client: The client component of wolfHSM is a library that can be linked
 against user applications. It provides APIs for sending requests to the
 server and receiving responses. The client abstracts the complexities of
 communication and ensures that the application can interact with the HSM
 securely and efficiently.

## Ports

wolfHSM is a library that provides an API for cryptographic operations, key management, and non-volatile storage, but itself is not executable and it does not contain any code to interact with any specific hardware. In order for wolfHSM to run on a specific device, the library must be configured with the necessary hardware drivers and abstraction layers such that the server application can run and communicate with the client. Specifically, getting wolfHSM to run on real hardware requires implementation of:

- Server application startup and hardware initialization
- Server wolfCrypt configuration
- Server non-volatile memory configuration
- Server and client transport configuration
- Server and client connection handling

The code that provides these requirements and wraps the server API into a bootable application is collectively referred to as a wolfHSM "port".

Official ports of wolfHSM are provided for various supported architectures, with each port providing the implementation of the wolfHSM abstractions tailored to the specific device. Each port contains:

- Standalone Reference Server Application: This application is meant to run on the HSM core, handling all secure operations. It comes fully functional out-of-the-box, but can also be customized by the end user to support additional use cases
- Client Library: This library can be linked against user applications to facilitate communication with the server

### Supported Ports

wolfHSM has supported ports for the following devices/environments:

- POSIX runtime
- ST Micro SPC58N\*
- Infineon Aurix TC3xx\*
- Infineon Aurix TC4xx\* (coming soon)
- Infineon Traveo T2G\* (coming soon)
- Renesas RH850\* (coming soon)
- Renesas RL78\* (coming soon)
- NXP S32\* (coming soon)

With additional ports on the way.

\* These ports unfortunately require an NDA with the silicon vendor to obtain any information about the HSM core. Therefore the wolfHSM ports for these platforms are not public and are only available to qualified customers. If you wish to access a restricted port of wolfHSM, please get in contact with us at support@wolfssl.com.

## Getting Started Using wolfHSM

The most common use case for wolfHSM is adding HSM-enabled functionality to an existing application running on one of the application cores of an automotive multi-core device with an HSM coprocessor. First, it is necessary to follow the steps in the specific wolfHSM port for the target device in order to get the reference server running on the HSM core. Once the wolfHSM server app is loaded on the device and boots, client applications can link against the wolfHSM client library, configure an instance of the wolfHSM client structure, and interact with the HSM through the wolfHSM client API and through the wolfCrypt API. Each wolfHSM port contains a client demo app showing how to set up the default communication channel and interact with the server. The server reference implementation can also be customized through [server callbacks](#server-callbacks) to extend its functionality.

### Basic Client Configuration

Configurating a wolfHSM client involves allocating a client context structure and initializing it with a valid client configuration that enables it to communicate with a server.

The client context structure `whClientContext` holds the internal state of the client and its communication with the server. All client APIs take a pointer to the client context.

The client configuration structure holds the communication layer configuration (`whCommClientConfig`) that will be used to configure and initialize the context for the server communication. The `whCommClientConfig` structure binds an actual transport implementation (either built-in or custom) to the abstract comms interface for the client to use.

The general steps to configure a client are:

1. Allocate and initialize a transport configuration structure, context, and callback implementation for the desired transport
2. Allocate and comm client configuration structure and bind it to the transport configuration from step 1 so it can be used by the client
3. Allocate and initialize a client configuration structure using the comm client configuration in step 2
4. Allocate a client context structure
5. Initialize the client with the client configuration by calling `wh_Client_Init()`
6. Use the client APIs to interact with the server

Here is a bare-minimum example of configuring a client application to use the built-in shared memory transport to send an echo request to the server

```c
    #include <string.h> /* for memcmp() */
    #include "wolfhsm/client.h"  /* Client API (includes comm config) */
    #include "wolfhsm/wh_transport_mem.h" /* transport implementation */

    /* Step 1: Allocate and initialize the shared memory transport configuration */
    /* Shared memory transport configuration */
    static whTransportMemConfig transportMemCfg = { /* shared memory config */ };
    /* Shared memory transport context (state) */
    whTransportMemClientContext transportMemClientCtx = {0};
    /* Callback structure that binds the abstract comm transport interface to
     * our concrete implementation */
    whTransportClientCb transportMemClientCb = {WH_TRANSPORT_MEM_CLIENT_CB};

    /* Step 2: Allocate client comm configuration and bind to the transport */
    /* Configure the client comms to use the selected transport configuration */
    whCommClientConfig commClientCfg[1] = {{
                 .transport_cb      = transportMemClientCb,
                 .transport_context = (void*)transportMemClientCtx,
                 .transport_config  = (void*)transportMemCfg,
                 .client_id         = 123, /* unique client identifier */
    }};

    /* Step 3: Allocate and initialize the client configuration */
    whClientConfig clientCfg= {
       .comm = commClientCfg,
    };

    /* Step 4: Allocate the client context */
    whClientContext clientCtx = {0};

    /* Step 5: Initialize the client with the provided configuration */
    wh_Client_Init(&clientCtx, &clientCfg);

    /* Step 6: Use the client APIs to interact with the server */

    /* Buffers to hold sent and received data */
    char recvBuffer[WH_COMM_DATA_LEN] = {0};
    char sendBuffer[WH_COMM_DATA_LEN] = {0};

    uint16_t sendLen = snprintf(&sendBuffer,
                                sizeof(sendBuffer),
                                "Hello World!\n");
    uint16_t recvLen = 0;

    /* Send an echo request and block on receiving a response */
    wh_Client_Echo(client, sendLen, &sendBuffer, &recvLen, &recvBuffer);

    if ((recvLen != sendLen ) ||
        (0 != memcmp(sendBuffer, recvBuffer, sendLen))) {
        /* Error, we weren't echoed back what we sent */
    }
```

While there are indeed a large number of nested configurations and structures to set up, designing wolfHSM this way allowed for different transport implementations to be swapped in and out easily without changing the client code. For example, in order to switch from the shared memory transport to a TCP transport, only the transport configuration and callback structures need to be changed, and the rest of the client code remains the same (everything after step 2 in the sequence above).

```c
    #include <string.h> /* for memcmp() */
    #include "wolfhsm/client.h"  /* Client API (includes comm config) */
    #include "port/posix_transport_tcp.h" /* transport implementation */

    /* Step 1: Allocate and initialize the posix TCP transport configuration */
    /* Client configuration/contexts */
    whTransportClientCb posixTransportTcpCb = {PTT_CLIENT_CB};
    posixTransportTcpClientContext posixTranportTcpCtx = {0};
    posixTransportTcpConfig posixTransportTcpCfg = {
        /* IP and port configuration */
    };

    /* Step 2: Allocate client comm configuration and bind to the transport */
    /* Configure the client comms to use the selected transport configuration */
    whCommClientConfig commClientCfg = {{
                 .transport_cb      = posixTransportTcpCb,
                 .transport_context = (void*)posixTransportTcpCtx,
                 .transport_config  = (void*)posixTransportTcpCfg,
                 .client_id         = 123, /* unique client identifier */
    }};

    /* Subsequent steps remain the same... */

```

### Basic Server Configuration

*Note: A wolfHSM port comes with a reference server application that is already configured to run on the HSM core and so manual server configuration is not required.*

Configuring a wolfHSM server involves allocating a server context structure and initializing it with a valid client configuration that enables it to perform the operations requested of it. These operations usually include client communication, cryptographic operations, and managing keys and non-volatile object storage. Not all of these components of the configuration need to be initialized, depending on the required functionality.

Steps required to configure a server that supports client communication, NVM object storage using the NVM flash configuration, and local crypto (software only) are:

1. Initialize the server comms configuration
    1. Allocate and initialize a transport configuration structure, context, and callback implementation for the desired transport
    2. Allocate and initialize a comm server configuration structure using the transport configuration from step 1.1
2. Initialize the server NVM context
    1. Allocate and initialize a config, context, and callback structure for the NVM flash storage drivers (the implementation of these structures is provided by the port)
    2. Allocate and initialize an NVM config structure using the NVM flash configuration from step 2.1
    3. Allocate an NVM context structure and initialize it with the configuration from step 2.2 using `wh_Nvm_Init()`
3. Allocate and initialize a crypto context structure for the server
4. Initialize wolfCrypt (before initializing the server)
5. Allocate and initialize a server config structure and bind the comm server configuration, NVM context, and crypto context to it
6. Allocate a server context structure and initialize it with the server configuration using `wh_Server_Init()`
7. Set the server connection state to connected using `wh_Server_SetConnected()` when the underlying transport is ready to be used for client communication (see [TODO](todo) for more information)
8. Process client requests using `wh_Server_HandleRequestMessage()`


```c
 /* TODO: basic server configuration example */
```



## Library Design / wolfHSM Internals

### Generic Component Architecture

To support easily porting wolfHSM to different hardware platforms and build
environments, each component of wolfHSM is designed to have a common initialization,
configuration, and context storage architecture to allow compile-time, link-
time, and/or run-time selection of functional components.  Hardware specifics
are abstracted from the logical operations by associating callback functions
with untyped context structures, referenced as a `void*`.

#### Example component initialization

The prototypical compile-time static instance configuration and initialization
sequence of a wolfHSM component is:

```c
#include "wolfhsm/component.h"        /* wolfHSM abstract API reference for a component */
#include "port/vendor/mycomponent.h"  /* Platform specific definitions of configuration
                                       * and context structures, as well as declarations of
                                       * callback functions */ 

/* Provide the lookup table for function callbacks for mycomponent. Note the type
is the abstract type provided in wolfhsm/component.h */
whComponentCb my_cb[1] = {MY_COMPONENT_CB};

/* Fixed configuration data.  Note that pertinent data is copied out of the structure 
 * during init() */
const myComponentConfig my_config = {
    .my_number = 3,
    .my_string = "This is a string",
}

/* Static allocation of the dynamic state of the myComponent. */
myComponentContext my_context[1] = {0};

/* Initialization of the component using platform-specific callbacks */
const whComponentConfig comp_config[1] = {
        .cb = my_cb,
        .context = my_context,
        .config = my_config
    };
whComponentContext comp_context[1] = {0};
int rc = wh_Component_Init(comp_context, comp_config);

rc = wh_Component_DoSomething(comp_context, 1, 2, 3);
rc = wh_Component_CleanUp(comp_context);
```

## wolfHSM Server

The wolfHSM server API 

## wolfHSM Client


## Communications

The wolfHSM server receives and responds to multiple clients' requests via wolfHSM's abstract communication interfaces. All communications are packet-based with a fixed-size header that a transport provides to the library for message processing. The split request and response processing supports synchronous polling of message reception or asynchronous handling based on interrupt/event support.

The abstract communications interface for both server and client is defined in [wh_comm.h](wolfhsm/wh_comm.h). The server and client configuration structures both take respective server and client comm config structures that hold a concrete implementation of the interface

```c
wh_CommClientInit();
wh_CommClientSendRequest();
wh_CommClientRecvResponse();
wh_CommClientCleanup();

wh_CommServerInit();
wh_CommServerRecvRequest();
wh_CommServerSendResponse();
wh_CommServerCleanup();
```

### Example Split Transaction Processing

```c
wh_ClientInit(context, config);

uint16_t req_magic = wh_COMM_MAGIC_NATIVE;
uint16_t req_type = 123;
uint16_t request_id;
char* req_data = "RequestData";
rc = wh_ClientSendRequest(context, req_magic, req_type, &request_id, 
                    sizeof(req_data), req_data);
/* Do other work */

uint16_t resp_magic, resp_type, resp_id, resp_size;
char response_data[20];
while((rc = wh_ClientRecvResponse(context,&resp_magic, &resp_type, &resp_id,
                    &resp_size, resp_data)) == WH_ERROR_NOTREADY) {
        /* Do other work or yield */
}
```

### Messages

Messages comprise a header with a variable length payload.  The header indicates
the sequence id, and type of a request or response.  The header also provides 
additional fields to provide auxiliary flags or session information. Each client
is only allowed a single outstanding request to the server at a time.  The
server will process a single request at a time to ensure client isolation.

Messages are used to encapsulate the request data necessary for the server to 
execute the desired function and for the response to provide the results of the
function execution back to the client.  Message types are grouped based on the 
component that is performing the function and uniquely identify which of the
enumerated functions is being performed.  To ensure compatibility (endianness,
and version), messages include a Magic field which has known values used to 
indicate what operations are necessary to demarshall data passed within the 
payload for native processing.  Each functional component has a "remote" 
implementation that converts between native values and the "on-the-wire" message
formats.  The servers ensures the response format matches the request format.

In addition to passing data contents within messages, certain message types also
support passing shared or mapped memory pointers, especially for performance-
critical operations where the server component may be able to directly access
the data in a DMA fashion.  To avoid integer pointer size (IPS) and size_t
differences, all pointers and sizes should be sent as uint64_t when
possible.

Messages are encoded in the "on-the-wire" format using the Magic field of the 
header indicating the specified endianness of structure members as well as the
version of the communications header (currently 0x01).  Server components that 
process request messages translate the provided values into native format, 
perform the task, and then reencode the result into the format of the request.
Client response handling is not required to process messages that do not match
the request format. Encoded messages assume the same size and layout as the
native structure, with the endianness specified by the Magic field.

Transport errors passed into the message layer are expected to be fatal and the
client/server should Cleanup any context as a result.


## Transport

Transports provide intact packets (byte sequences) of variable size (up to a
maximum MTU), to the messaging layer for the library to process as a request or 
response.

```c
wh_TransportInit();
wh_TransportSend();
wh_TransportRecv();
wh_TransportCleanup();
```


## Non Volatile Memory

## Cryptographic Operations

## AUTOSAR SHE 

## wolfHSM Functional Components

The wolfHSM server provides the combination of non-volatile object storage,
persistent key and counter management, boot image management, and offloaded
(hardware accelerated) cryptographic operations within an isolated and securable
environment that is tailored to available hardware features.

```c
wh_NvmInit();
wh_NvmCleanup();

wh_KcInit();
wh_KcCleanup();

wh_ImageInit();
wh_ImageCleanup();

wh_CryptoInit();
wh_CryptoCleanup();
```

## Client/Server Roles

The wolfHSM client library and server application provide top-level features
that combine the communication and message handling functions to simplify usage.
The wolfHSM server application follows a strict startup sequence and

## Communication Client/Server

The wolfHSM server responds to with multiple clients' requests via communcation
interfaces.  All communications are packet-based with a fixed-size header that
a transport provides to the library for message processing.  The split request
and response processing supports synchronous polling of message reception or
asynchronous handling based on interrupt/event support.

```c
wh_CommClientInit();
wh_CommClientSendRequest();
wh_CommClientRecvResponse();
wh_CommClientCleanup();

wh_CommServerInit();
wh_CommServerRecvRequest();
wh_CommServerSendResponse();
wh_CommServerCleanup();
```

### Example Split Transaction Processing

```c
wh_ClientInit(context, config);

uint16_t req_magic = wh_COMM_MAGIC_NATIVE;
uint16_t req_type = 123;
uint16_t request_id;
char* req_data = "RequestData";
rc = wh_ClientSendRequest(context, req_magic, req_type, &request_id, 
                    sizeof(req_data), req_data);
/* Do other work */

uint16_t resp_magic, resp_type, resp_id, resp_size;
char response_data[20];
while((rc = wh_ClientRecvResponse(context,&resp_magic, &resp_type, &resp_id,
                    &resp_size, resp_data)) == WH_ERROR_NOTREADY) {
        /* Do other work or yield */
}
```

## Messages

Messages comprise a header with a variable length payload.  The header indicates
the sequence id, and type of a request or response.  The header also provides 
additional fields to provide auxiliary flags or session information. Each client
is only allowed a single outstanding request to the server at a time.  The
server will process a single request at a time to ensure client isolation.

Messages are used to encapsulate the request data necessary for the server to 
execute the desired function and for the response to provide the results of the
function execution back to the client.  Message types are grouped based on the 
component that is performing the function and uniquely identify which of the
enumerated functions is being performed.  To ensure compatibility (endianness,
and version), messages include a Magic field which has known values used to 
indicate what operations are necessary to demarshall data passed within the 
payload for native processing.  Each functional component has a "remote" 
implementation that converts between native values and the "on-the-wire" message
formats.  The servers ensures the response format matches the request format.

In addition to passing data contents within messages, certain message types also
support passing shared or mapped memory pointers, especially for performance-
critical operations where the server component may be able to directly access
the data in a DMA fashion.  To avoid integer pointer size (IPS) and size_t
differences, all pointers and sizes should be sent as uint64_t when
possible.

Messages are encoded in the "on-the-wire" format using the Magic field of the 
header indicating the specified endianness of structure members as well as the
version of the communications header (currently 0x01).  Server components that 
process request messages translate the provided values into native format, 
perform the task, and then reencode the result into the format of the request.
Client response handling is not required to process messages that do not match
the request format. Encoded messages assume the same size and layout as the
native structure, with the endianness specified by the Magic field.

Transport errors passed into the message layer are expected to be fatal and the
client/server should Cleanup any context as a result.


## Transport

Transports provide intact packets (byte sequences) of variable size (up to a
maximum MTU), to the messaging layer for the library to process as a request or 
response.

### API's

wh_TransportInit();
wh_TransportSend();
wh_TransportRecv();
wh_TransportCleanup();
