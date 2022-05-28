/*
 * Copyright 2022 - 2022, Catherine Kelly
 * SPDX-License-Identifier: CC0-1.0 OR Unlicense
 */

// @ts-nocheck

let events = require("node:events");
let stream = require("node:stream");
let net = require("node:net");
let crypto = require("node:crypto");

events.prototype.waitEvent = function (...eventNames) {
	return new Promise((resolve) => {
		let listeners = new Map();
		let listener = (...args) => {
			for (let eventName of eventNames) {
				this.removeListener(eventName, listeners.get(eventName));
			}
			resolve(args);
		};
		for (let eventName of eventNames) {
			listeners.set(eventName, (...args) => listener(eventName, ...args));
			this.once(eventName, listeners.get(eventName));
		}
	});
};

stream.prototype.dEnd = function () {
	return new Promise((resolve) => {
		if (this.writable) {
			this.end(() => {
				if (!this.destroyed) {
					this.destroy();
					resolve();
				}
			});
		} else if (!this.destroyed) {
			this.destroy();
			resolve();
		}
	});
};

stream.prototype.pWrite = function (data) {
	return new Promise(this.write.bind(this, data));
};

stream.prototype.dWrite = async function (data) {
	if (!this.writable) {
		throw new Error("Stream is not writable");
	}
	if (this.writableNeedDrain) {
		if ((await this.waitEvent("drain", "close"))[0] === "close") {
			throw new Error("Stream ended while waiting to write data");
		}
	}
	if (!this.writable) {
		throw new Error("Stream is not writable");
	}
	return await this.pWrite(data);
};

stream.prototype.dRead = async function (length) {
	if (!this.pushBackBuffer) {
		this.pushBackBuffer = Buffer.alloc(0);
	}

	if (length === 0) {
		return Buffer.alloc(0);
	}
	while (this.pushBackBuffer.length < length) {
		let newData = this.read(Math.min(length - this.pushBackBuffer.length, this.readableLength));
		if (newData) {
			this.pushBackBuffer = Buffer.concat([this.pushBackBuffer, newData]);
		} else {
			if (this.readableLength !== 0) {
				throw new Error("LOGICLY IMPOSSIBLE: Unexpected read() behaviour");
			}
		}
		if (this.pushBackBuffer.length >= length) {
			break;
		}
		if (this.readableLength === 0) {
			if ((await this.waitEvent("readable", "end"))[0] === "end") {
				throw new Error("Stream ended while waiting for data");
			}
		} else {
			throw new Error("LOGICLY IMPOSSIBLE: Unexpected read() behaviour");
		}
	}
	return [this.pushBackBuffer.slice(0, length), this.pushBackBuffer = this.pushBackBuffer.slice(length)][0];
};

global.SMC = (n, fn) => {
	return new Proxy(Object, {
		construct: function (_target, argArray, _newTarget) {
			return (...args) => {
				argArray = argArray.slice(0, n).concat([undefined].repeat(n - argArray.length));
				return fn(...argArray, ...args);
			};
		},
		apply: function (_target, _thisArg, argumentsList) {
			return (...args) => {
				argumentsList = argumentsList.slice(0, n).concat([undefined].repeat(n - argumentsList.length));
				return fn(...argumentsList, ...args);
			};
		}
	});
};

Function.prepArg = function () {
	this.bind(null, prepArg);
};

Array.prototype.repeat = function (n) {
	let r = [];
	for (let i = 0; i < n; i++) {
		r = r.concat(this);
	}
	return r;
};

net.formatIPv6 = (addr) => {
	addr = addr.replace("::", ":X:");
	addr = addr.split(":");
	if (addr.length !== 8 || addr.includes("X")) {
		addr.splice(addr.indexOf("X"), 1, ...(["0000"].repeat(8 - addr.length + 1)));
	}
	for (let i in addr) {
		addr[i] = "0".repeat(4 - addr[i].length) + addr[i];
	}

	return addr.join(":");
};

net.ConnectionListener = SMC(2, async (connectionHandler, logger, socket) => {

	socket.id = crypto.randomBytes(8).toString("hex");

	logger(`socket ${socket.id}`, "log", "new connection");

	socket.on("error", (error) => {
		logger(`socket ${socket.id}`, "error", error);
		socket.dEnd();
	});

	socket.on("close", () => {
		logger(`socket ${socket.id}`, "log",  "closed");
		socket.dEnd();
	});

	try {
		await connectionHandler(logger.bind(null, `socket ${socket.id}`, "log"), socket);
		await socket.dEnd();
	} catch (error) {
		logger(`socket ${socket.id}`, "error", error);
		socket.dEnd();
	}
});