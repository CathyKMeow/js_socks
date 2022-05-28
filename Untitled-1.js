/*
 * Copyright 2022 - 2022, Catherine Kelly
 * SPDX-License-Identifier: CC0-1.0 OR Unlicense
 */

// @ts-nocheck

let net = require("node:net");
let socksSrv = require("./socksSrv");

let server = new net.Server();

server.on("error", (...args) => console.error(...args));
server.on("connection", new net.ConnectionListener(
	new socksSrv.SocksConnectionHandler({
		authMethods: ["userPass"],
		checkUserPass: new socksSrv.DefaultCheckUserPass(new Map(Object.entries({
			"user1": "pass1",
			"user2": "pass2",
			"user3": "pass3",
		})))
	}),
	(...args) => console.log("socks server", ...args))
);

server.listen(1234);