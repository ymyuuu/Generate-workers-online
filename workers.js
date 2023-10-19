//	Author: Mingyu,Last Modified: 2023-10-20 UTC
//	在线生成 Cloudflare Workers 配置
//	https://workers-vless.vercel.app/

import { connect } from 'cloudflare:sockets';

let userID = 'uuid';

const proxyIPs = [];

let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

let dohURL = 'https://dns.alidns.com/dns-query'; // https://cloudflare-dns.com/dns-query or https://dns.google/dns-query

// v2board api environment variables (optional) deprecated, please use planetscale.com instead

if (!isValidUUID(userID)) {
	throw new Error('uuid is invalid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		uuid_validator(request);
		try {
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;
			dohURL = env.DNS_RESOLVER_URL || dohURL;
			// nodeId = env.NODE_ID || nodeId;
			// apiToken = env.API_TOKEN || apiToken;
			// apiHost = env.API_HOST || apiHost;
			let userID_Path = userID;
			if (userID.includes(',')) {
				userID_Path = userID.split(',')[0];
			}
			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case '/cf':
						return new Response(JSON.stringify(request.cf, null, 4), {
							status: 200,
							headers: {
								"Content-Type": "application/json;charset=utf-8",
							},
						});
					case `/${userID_Path}`: {
						const vlessConfig = getVLESSConfig(userID, request.headers.get('Host'));
						return new Response(`${vlessConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/html; charset=utf-8",
							}
						});
					}
					case `/sub/${userID_Path}`: {
						const url = new URL(request.url);
						const searchParams = url.searchParams;
						let vlessConfig = createVLESSSub(userID, request.headers.get('Host'));

						// If 'format' query param equals to 'clash', convert config to base64
						if (searchParams.get('format') === 'clash') {
							vlessConfig = btoa(vlessConfig);
						}

						// Construct and return response object
						return new Response(vlessConfig, {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					}
					default:
						// return new Response('Not found', { status: 404 });
						// For any other path, reverse proxy to 'www.fmprc.gov.cn' and return the original response, caching it in the process
						const hostnames = ['www.fmprc.gov.cn', 'www.xuexi.cn', 'www.gov.cn', 'mail.gov.cn', 'www.mofcom.gov.cn', 'www.gfbzb.gov.cn', 'www.miit.gov.cn', 'www.12377.cn'];
						url.hostname = hostnames[Math.floor(Math.random() * hostnames.length)];
						url.protocol = 'https:';

						const newHeaders = new Headers(request.headers);
						newHeaders.set('cf-connecting-ip', newHeaders.get('x-forwarded-for') || newHeaders.get('cf-connecting-ip'));
						newHeaders.set('x-forwarded-for', newHeaders.get('cf-connecting-ip'));
						newHeaders.set('x-real-ip', newHeaders.get('cf-connecting-ip'));
						newHeaders.set('referer', 'https://www.google.com/q=edtunnel');

						request = new Request(url, {
							method: request.method,
							headers: newHeaders,
							body: request.body,
							redirect: request.redirect,
						});

						const cache = caches.default;
						let response = await cache.match(request);

						if (!response) {
							try {
								response = await fetch(request, { redirect: 'manual' });
							} catch (err) {
								url.protocol = 'http:';
								url.hostname = hostnames[Math.floor(Math.random() * hostnames.length)];
								request = new Request(url, {
									method: request.method,
									headers: newHeaders,
									body: request.body,
									redirect: request.redirect,
								});
								response = await fetch(request, { redirect: 'manual' });
							}

							const cloneResponse = response.clone();
							ctx.waitUntil(cache.put(request, cloneResponse));
						}
						return response;
				}
			} else {
				return await vlessOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

export async function uuid_validator(request) {
	const hostname = request.headers.get('Host');
	const currentDate = new Date();

	const subdomain = hostname.split('.')[0];
	const year = currentDate.getFullYear();
	const month = String(currentDate.getMonth() + 1).padStart(2, '0');
	const day = String(currentDate.getDate()).padStart(2, '0');

	const formattedDate = `${year}-${month}-${day}`;

	// const daliy_sub = formattedDate + subdomain
	const hashHex = await hashHex_f(subdomain);
	// subdomain string contains timestamps utc and uuid string TODO.
	console.log(hashHex, subdomain, formattedDate);
}

export async function hashHex_f(string) {
	const encoder = new TextEncoder();
	const data = encoder.encode(string);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
	return hashHex;
}

/**
 * Handles VLESS over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the VLESS header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
async function vlessOverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	let currentDate = new Date();
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processVlessHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
			if (hasError) {
				// controller.error(message);
				throw new Error(message); // cf seems has bug, controller.error will not end stream
				// webSocket.close(1000, message);
				return;
			}

			// If UDP and not DNS port, close it
			if (isUDP && portRemote !== 53) {
				throw new Error('UDP proxy only enabled for DNS which is port 53');
				// cf seems has bug, controller.error will not end stream
			}

			if (isUDP && portRemote === 53) {
				isDns = true;
			}

			// ["version", "附加信息长度 N"]
			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			// TODO: support udp here when cf runtime has udp support
			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket 
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log,) {

	/**
	 * Connects to a given address and port and writes data to the socket.
	 * @param {string} address The address to connect to.
	 * @param {number} port The port to connect to.
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} A Promise that resolves to the connected socket.
	 */
	async function connectAndWrite(address, port) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); // first write, nomal is tls client hello
		writer.releaseLock();
		return tcpSocket;
	}

	/**
	 * Retries connecting to the remote address and port if the Cloudflare socket has no incoming data.
	 * @returns {Promise<void>} A Promise that resolves when the retry is complete.
	 */
	async function retry() {
		const tcpSocket = await connectAndWrite(proxyIP || addressRemote, portRemote)
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	const tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// when remoteSocket is ready, pass to websocket
	// remote--> ws
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer The WebSocket server to create the readable stream from.
 * @param {string} earlyDataHeader The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				controller.close();
			});

			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
			// if ws can stop read if stream is full, we can implement backpressure
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},

		cancel(reason) {
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * Processes the VLESS header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} vlessBuffer The VLESS header buffer to process.
 * @param {string} userID The user ID to validate against the UUID in the VLESS header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  vlessVersion?: Uint8Array,
 *  isUDP?: boolean
 * }} An object with the relevant information extracted from the VLESS header buffer.
 */
function processVlessHeader(vlessBuffer, userID) {
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);
	// check if userID is valid uuid or uuids split by , and contains userID in it otherwise return error message to console
	const uuids = userID.includes(',') ? userID.split(",") : [userID];
	// uuid_validator(hostName, slicedBufferString);


	// isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim());
	isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();

	console.log(`userID: ${slicedBufferString}`);

	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	//skip opt for now

	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
		isUDP = false;
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1--> ipv4  addressLength =4
	// 2--> domain name addressLength=addressBuffer[1]
	// 3--> ipv6  addressLength =16
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP,
	};
}


/**
 * Converts a remote socket to a WebSocket connection.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} vlessResponseHeader The VLESS response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	// remote--> ws
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false; // check if remoteSocket has incoming data
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				/**
				 * 
				 * @param {Uint8Array} chunk 
				 * @param {*} controller 
				 */
				async write(chunk, controller) {
					hasIncomingData = true;
					remoteChunkCount++;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						// console.log(`remoteSocketToWS send chunk ${chunk.byteLength}`);
						// seems no need rate limit this, CF seems fix this??..
						// if (remoteChunkCount > 20000) {
						// 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
						// 	await delay(1);
						// }
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
					// safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	// seems is cf connect socket have error,
	// 1. Socket.closed will have error
	// 2. Socket.readable will be close without any data coming
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: null, error: null };
	}
	try {
		// go use modified Base64 for URL rfc4648 which js atob not support
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: null, error };
	}
}

/**
 * Checks if a given string is a valid UUID.
 * Note: This is not a real UUID validation.
 * @param {string} uuid The string to validate as a UUID.
 * @returns {boolean} True if the string is a valid UUID, false otherwise.
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Closes a WebSocket connection safely without throwing exceptions.
 * @param {import("@cloudflare/workers-types").WebSocket} socket The WebSocket connection to close.
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}


/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} vlessResponseHeader The VLESS response header.
 * @param {(string) => void} log The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {

	let isVlessHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {

		},
		transform(chunk, controller) {
			// udp message 2 byte is the the length of udp data
			// TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPakcetLength)
				);
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {
		}
	});

	// only handle dns udp for now
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch(dohURL, // dns server url
				{
					method: 'POST',
					headers: {
						'content-type': 'application/dns-message',
					},
					body: chunk,
				})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			// console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh success and dns message length is ${udpSize}`);
				if (isVlessHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isVlessHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('dns udp has error' + error)
	});

	const writer = transformStream.writable.getWriter();

	return {
		/**
		 * 
		 * @param {Uint8Array} chunk 
		 */
		write(chunk) {
			writer.write(chunk);
		}
	};
}

/**
 *
 * @param {string} userID - single or comma separated userIDs
 * @param {string | null} hostName
 * @returns {string}
 */



// 1.更灵活的URL生成规则： 旧代码中的 `commonUrlPart` 生成规则是基于 `hostName` 是否以 "workers.dev" 结尾来选择端口号和安全性，新代码中更加灵活，不仅根据 `hostName` 判断安全性，还根据 `hostName` 和代理IP (`proxyIP`) 的情况选择相应的端口号和安全性。

// 2.更具个性化的标题和描述： 更新后的代码在生成HTML头部时，增加了针对项目的更具个性的标题和描述。它引用了一个名为 "Mingyu" 的项目，为生成的页面添加了更多描述性的内容。

// 3.定制化的Clash节点订阅链接： 更新后的代码生成Clash节点订阅链接时，包括了一些不同的参数，例如 `sort`、`emoji`、`list` 等，使订阅链接更具定制化，以满足特定的需求。

// 4.Base64编码的节点信息： 在新代码中，生成VLESS配置时，节点信息被Base64编码，以提供更安全的方式传输节点信息。这增强了节点信息的隐私和安全性。


function getVLESSConfig(userIDs, hostName) {
    const commonUrlPart = `:${hostName.endsWith('workers.dev') ? '80' : '443'}?encryption=none&security=${hostName.endsWith('workers.dev') ? 'none' : 'tls'}&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${proxyIP}`;
    const separator = "---------------------------------------------------------------";
    const hashSeparator = "===============================================================";

    // 将用户ID拆分为数组
    let userIDArray = userIDs.split(',');

    // 准备输出数组
    let output = [];
    let header = [];
    let clashLink = ''; // 初始化 Clash 链接

    if (hostName.endsWith('workers.dev')) {
        // 只有当 hostName 以 "workers.dev" 结尾时才生成 Clash 链接
        const clash_link = `https://subconversion.ymy.gay/sub?target=clash&url=https://${hostName}/sub/${userIDArray[0]}&insert=false&config=https%3A%2F%2Fcdn.jsdelivr.net%2Fgh%2FSleepyHeeead%2Fsubconverter-config%40master%2Fremote-config%2Fcustomized%2Fark.ini&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
        clashLink = `<a href="${clash_link}" target="_blank">Clash节点订阅链接</a>`;
    }

    header.push(`<p align="center"><h1 style="text-align: center; font-size: 40px;">Node configuration for <span style="text-decoration: underline; cursor: pointer;" onclick="window.open('https://git.ymy.gay/', '_blank')">Mingyu</span></h1></p>`);
    header.push(`<div style="text-align: center;">`);
    header.push(`<a href="//${hostName}/sub/${userIDArray[0]}" target="_blank">VLESS节点订阅链接</a>`);
    header.push(`&nbsp;&nbsp;`); // 添加间距
    if (clashLink) {
        header.push(clashLink);
        header.push(`&nbsp;&nbsp;`); // 添加间距
    }
    header.push(`<a href="https://url.ymy.gay/" target="_blank">点击生成订阅短链接</a>`);
    header.push(`</div>`);

    // 为每个用户ID生成输出字符串
    userIDArray.forEach((userID) => {
        const vlessSec = `vless://${userID}@${proxyIP}${commonUrlPart}`;
        output.push("© 2023 Mingyu<br><br>");
        output.push(`UUID: ${userID}<br>`);
        output.push(`Ports: 80, 8080, 8880, 2052, 2086, 2095, 443, 8443, 2053, 2096, 2087, 2083`);
        output.push(`http port: 80, 8080, 8880, 2052, 2086, 2095`);
        output.push(`https port: 443, 8443, 2053, 2096, 2087, 2083<br>`);
        output.push(`${hashSeparator}\n\nV2ray-vless\n${separator}\n${vlessSec}\n${separator}`);
    });
    output.push(`\nClash-yaml\n${separator}\nproxy-groups:\n  - name: UseProvider\n    type: select\n    use:\n      - provider1\n    proxies:\n      - Proxy\n      - DIRECT\nproxy-providers:\n  provider1:\n    type: http\n    interval: 3600\n    path: ./provider1.yaml\n    health-check:\n      enable: true\n      interval: 600\n      # lazy: true\n      url: http://www.gstatic.com/generate_204\n${separator}`);

    // HTML头部和CSS
    const htmlHead = `
	<head>
    <title>Mingyu's configuration</title>
    <meta name="description" content="这是一个用于生成VLESS协议配置的工具。">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta property="og:site_name" content="Mingyu's configuration" />
    <meta property="og:type" content="website" />
    <meta property="og:title" content="Mingyu - VLESS配置和订阅输出" />
    <meta property="og:description" content="使用Cloudflare Pages和Worker实现VLESS协议" />
    <meta property="og:url" content="https://${hostName}/" />
    <meta property="og:image" content="https://api.qrserver.com/v1/create-qr-code/?size=500x500&data=${encodeURIComponent(`vless://${userIDs.split(',')[0]}@${hostName}${commonUrlPart}`)}" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:title" content="Mingyu - VLESS配置和订阅输出" />
    <meta name="twitter:description" content="使用Cloudflare Pages和Worker实现VLESS协议" />
    <meta name="twitter:url" content="https://${hostName}/" />
    <meta name="twitter:image" content="https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky" />
    <meta property="og:image:width" content="1500" />
    <meta property="og:image:height" content="1500" />


        <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            color: #333;
            padding: 10px;
        }

        a {
            color: #1a0dab;
            text-decoration: none;
        }
        img {
            max-width: 100%;
            height: auto;
        }

        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            background-color: #fff;
            border: 1px solid #ddd;
            padding: 15px;
            margin: 10px 0;
        }
        /* 暗黑模式 */
        @media (prefers-color-scheme: dark) {
            body {
                background-color: #333;
                color: #f0f0f0;
            }

            a {
                color: #9db4ff;
            }

            pre {
                background-color: #282a36;
                border-color: #6272a4;
            }
        }
        </style>
    </head>
    `;

    // 将输出连接到换行符中，包装在<html>和<body>内
    return `
    <html>
    ${htmlHead}
    <body>
    <pre style="
    background-color: transparent;
    border: none;
">${header.join('')}</pre><pre>${output.join('\n')}</pre>
    </body>
</html>`;
}


function createVLESSSub(userID_Path, hostName, selectedProxyIP) {
    let portArray_http = [80, 8080, 8880, 2052, 2086, 2095, 2082];
    let portArray_https = [443, 8443, 2053, 2096, 2087, 2083];

    // 将用户ID拆分为数组
    let userIDArray = userID_Path.includes(',') ? userID_Path.split(',') : [userID_Path];

    // 准备输出数组
    let output = [];

    // 为每个用户ID生成输出字符串
    userIDArray.forEach((userID) => {
        let nodeInfo = ''; // 初始化节点信息

        // 检查hostName是否为Cloudflare Pages域名，如果是，则生成HTTP配置，否则生成HTTP和HTTPS配置
        if (hostName.endsWith('workers.dev')) {
            // 针对HTTP遍历所有端口
            portArray_http.forEach((port) => {
                const commonUrlPart_http = `:${port}?encryption=none&security=none&fp=random&type=ws&host=${hostName}&path=%2F%3D2048#Sub-${port}`;
                const vlessMainHttp = `vless://${userID}@${proxyIP}${commonUrlPart_http}`;
                nodeInfo += vlessMainHttp + '\n';
            });
        } else {
            // 针对HTTP和HTTPS遍历所有端口
            portArray_http.forEach((port) => {
                const commonUrlPart_http = `:${port}?encryption=none&security=none&fp=random&type=ws&host=${hostName}&path=%2F%3D2048#Sub-${port}`;
                const vlessMainHttp = `vless://${userID}@${proxyIP}${commonUrlPart_http}`;
                nodeInfo += vlessMainHttp + '\n';
            });

            portArray_https.forEach((port) => {
                const commonUrlPart_https = `:${port}?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#Sub-${port}`;
                const vlessMainHttps = `vless://${userID}@${proxyIP}${commonUrlPart_https}`;
                nodeInfo += vlessMainHttps + '\n';
            });
        }

        const base64NodeInfo = btoa(nodeInfo); // 将节点信息进行Base64编码
        output.push(base64NodeInfo);
    });

    // 连接Base64编码后的节点信息并使用换行符
    return output.join('\n');
}
