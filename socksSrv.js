/*
 * Copyright 2022 - 2022, Catherine Kelly
 * SPDX-License-Identifier: CC0-1.0 OR Unlicense
 */

// @ts-nocheck

let net = require("node:net");
require("./nodeEnhancements");

let socksSrv = module.exports;

socksSrv.DefaultConnectHandler = SMC(1, async (options = {}, logger, addrType, addr, port) => {
	if (addrType === "ipv4") {
		addr = Array.from(addr).join(".");
	}
	if (addrType === "ipv6") {
		addr = Array.from(addr).join("");
		let addrArr = [];
		for (let i = 0; i < 8; i++) {
			addrArr.push(addr.slice(i * 4, i * 4 + 4));
		}

		addr = addrArr.join(":");
	}

	logger(`address type: ${addrType}, address: ${addr}`);
	if (addrType === "dom" && options.forbiddenDomainList && options.forbiddenDomainList.includes(addr)) {
		return ["EPERM", null];
	}
	if (options.disallowed && await options.disallowed(addrType, addr)) { // TODO await
		return ["EPERM", null];
	}

	let connection = new net.Socket();
	let statusPromise = connection.waitEvent("connect", "error");
	connection.connect(port, addr);
	let status = await statusPromise;

	if (status[0] === "connect") {
		return ["SUCCESS", connection];
	} else {
		logger("failed", status[1]);
		return [status[1].code, null];
	}
});

socksSrv.socks5AddrPortFrom = (address, port) => {
	if (net.isIPv4(address)) {
		return Buffer.from([1].concat(address.split(".")).concat([port >> 8, port & 0b11111111]));
	} else if (net.isIPv6(address)) {
		return Buffer.concat([Buffer.from([4]), Buffer.from(net.formatIPv6(addr).replaceAll(":", ""), "hex"), Buffer.from([port >> 8, port & 0b11111111])]);
	} else {
		if (addr.length > 255) {
			throw new Error(`domain name length too long (${addr.length} > 255)`);
		}
		return Buffer.concat([Buffer.from([4, addr.length]), Buffer.from(addr), Buffer.from([port >> 8, port & 0b11111111])]);
	}
}

socksSrv.socksCommandHandlers = {
	5: {
		// Connect (1)
		1: async (options, logger, socket) => {
			logger("command is connect");

			let reserved = (await socket.dRead(1))[0];
	
			if (reserved !== 0) {
				throw new Error(`malformed request: reserved variable is not zero: ${reserved}`);
			}

			let addrTypeN = (await socket.dRead(1))[0], addrType, rawAddr, addr, rawPort, port;

			if (addrTypeN === 1) {
				addrType = "ipv4";
				rawAddr = await socket.dRead(4);
				addr = Array.from(rawAddr);
			} else if (addrTypeN === 3) {
				addrType = "dom";
				let lenAddr = (await socket.dRead(1));
				rawAddr = Buffer.concat([lenAddr, await socket.dRead(lenAddr[0])]);
				addr = rawAddr.slice(1).toString();
			} else if (addrTypeN === 4) {
				addrType = "ipv6";
				addr = Array.from(await socket.dRead(16));
			} else {
				socket.write(Buffer.from([5, 8, 0, 1, 0, 0, 0, 0, 0, 0]));
				throw new Error(`unsupported address type ${addrType}`);
			}

			rawPort = await socket.dRead(2);
			port = (rawPort[0] << 8) + rawPort[1];

			let [status, connection] = await options.connectHandler(logger.bind(null, "connect command"), addrType, addr, port);
			let nStatus = {
				SUCCESS: 0,
				EPERM: 2,
				ENETUNREACH: 3,
				EHOSTUNREACH: 4,
				ECONNREFUSED: 5,
				ETIME: 6,
				unsuppAddrType: 8,
			}[status];

			if (nStatus === undefined) {
				nStatus = 1;
			}

			socket.write(Buffer.concat([Buffer.from([5, status, 0]), socksSrv.socks5AddrPortFrom(connection.localAddress, connection.localPort)]));

			if (status !== "SUCCESS") {
				throw new Error(`connect command failed: ${status}`);
			}
			logger("connect command succeed");

			socket.pipe(connection);
			connection.pipe(socket);
			socket.on("close", connection.dEnd.bind(connection));
			connection.on("close", socket.dEnd.bind(socket));
			connection.on("error", socket.destroy.bind(socket));

			await socket.waitEvent("close");
		},

		// 2 3 TODO
	}
};

socksSrv.DefaultCheckUserPass = SMC(1, (userPassList, username, password) => {
	if (!userPassList.has(username) || userPassList.get(username) !== password) {
		return false;
	}
	return true;
});

socksSrv.socksAuthMethodHandlers = {
	5: {
		// None (0)
		0: async (_options, logger, _socket) => {
			logger("authentication skiped");
			return true;
		},

		// GSSAPI (1) TODO

		// Username / password (2)
		2: async (options, logger, socket) => {
			logger("authenticating by username / password");

			await socket.dRead(1);

			let lenUsername = (await socket.dRead(1))[0];
			let username = await socket.dRead(lenUsername);

			let lenPassword = (await socket.dRead(1))[0];
			let password = await socket.dRead(lenPassword);

			let suc = options.checkUserPass(username.toString(), password.toString());

			if (suc instanceof Promise) {
				suc = await suc;
			}
	
			socket.write(Buffer.from([5, Number(!suc)]));
			return suc;
		},
	}
};

socksSrv.socksConnectionHandlerByVersion = {
	5: async (options, logger, socket) => {

		let nAuthMethods = (await socket.dRead(1))[0], authSucceeded = false;

		if (nAuthMethods === 0) {
			throw new Error("malformed request: the client provides no auth methods");
		}

		let authMethods = Array.from(await socket.dRead(nAuthMethods));

		let authMethodNum = {
			none: 0,
			GSSAPI: 1,
			userPass: 2,
			...options.authMethodsNum[5]
		};

		for (let authMethod of options.authMethods) {
			authMethod = authMethodNum[authMethod];
			if (authMethods.includes(authMethod) && options.socksAuthMethodHandlers[5][authMethod]) {
				logger(`selecting authentication method ${authMethod}`);
				socket.write(Buffer.from([5, authMethod]));
				if (!await options.socksAuthMethodHandlers[5][authMethod](options, logger, socket)) {
					throw new Error("client authentication failed");
				} else {
					logger("client authentication succeeded");
					authSucceeded = true;
				}
			}
		}

		if (!authSucceeded) {
			socket.write(Buffer.from([5, 0xff]));
			await socket.dEnd();
			throw new Error("rejecting all auth methods the client provides");
		}

		if ((await socket.dRead(1))[0] !== 5) {
			throw new Error(`malformed request: version unsupported`);
		}
		
		let command = (await socket.dRead(1))[0];

		let commandsNum = {
			connect: 1,
			...options.commandsNum[5]
		};
		let acceptedCommends = [];
		for (let command of options.commands) {
			acceptedCommends.push(commandsNum[command])
		}

		if (acceptedCommends.includes(command) && options.socksCommandHandlers[5][command]) {
			await options.socksCommandHandlers[5][command](options, logger, socket);
		} else {
			socket.write(Buffer.from([5, 7, 0, 0]));
			throw new Error(`unsupported command ${command}`);
		}
	},
}

socksSrv.SocksConnectionHandler = SMC(1, async (options = {}, logger, socket) => {
	options = {
		versions: [5],
		socksConnectionHandlerByVersion: socksSrv.socksConnectionHandlerByVersion,
		authMethodsNum: {
			5: {},
		},
		commandsNum: {
			5: {},
		},
		authMethods: ["userPass"],
		socksAuthMethodHandlers: socksSrv.socksAuthMethodHandlers,
		socksCommandHandlers: socksSrv.socksCommandHandlers,
		connectHandler: new socksSrv.DefaultConnectHandler({}),
		commands: ["connect"],
		checkUserPass: new socksSrv.DefaultCheckUserPass(new Map(Object.entries({
			"user1": "pass1",
			"user2": "pass2",
		}))),
		...options
	};

	let version = (await socket.dRead(1))[0];

	if (options.versions.includes(version) && options.socksConnectionHandlerByVersion[version]) {
		logger(`version: ${version}`);
		await options.socksConnectionHandlerByVersion[version](options, logger, socket);
	} else {
		throw new Error(`version unsupported: ${version}`);
	}
	
	logger("session ended");
});
