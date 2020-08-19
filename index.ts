import * as matrixcs from "matrix-js-sdk";
import {Buffer} from "buffer";
import * as olm from "olm";

const passphrase: string = "secretphrase";

let loggedIn: boolean = false;
const key: string = "decryption key";

const ZERO_STR: string = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

async function getSecretStorageKey({keys}: {keys: {[propName: string]: any;}}, name: string): Promise<[string, Uint8Array]> {
    for (const [keyName, keyInfo] of Object.entries(keys)) {
        //const key = await deriveKey(passphrase, keyInfo.passphrase.salt, keyInfo.passphrase.iterations);
        const key = Uint8Array.of(36,47,159,193,29,188,180,86,189,180,207,101,79,255,93,159,
                                  228,43,160,158,98,209,84,196,137,122,119,118,11,131,75,87);
        const {mac} = await encryptAES(ZERO_STR, key, "", keyInfo.iv);
        if (keyInfo.mac.replace(/=+$/g, '') === mac.replace(/=+$/g, '')) {
            return [keyName, key];
        }
    }
    return null;
}

const cryptoCallbacks = {
    getSecretStorageKey: getSecretStorageKey,
    async getDehydrationKey() {
        return passphrase;
    },
    async generateDehydrationKey() {
        return {key: passphrase};
    }
};

let client = matrixcs.createClient({
    baseUrl: "http://localhost:8008",
    cryptoCallbacks: cryptoCallbacks,
} as any);

// fake localstorage
const dummyStore = {
    _data: {},
    _keys: [],
    getItem(name) {
        return this._data[name];
    },
    setItem(name, value) {
        this._data[name] = value;
        this._keys = Object.keys(this._data);
    },
    removeItem(name) {
        delete this._data[name];
        this._keys = Object.keys(this._data);
    },
    key(i) {
        return this._keys[i];
    },
    get length() {
        return this._keys.length;
    },
    reset() {
        this._data = {};
        this._keys = [];
    }
};

const log = {
    logdiv: null,
    init(): void {
        this.logdiv = document.getElementById("log");
    },
    log(str: string = undefined): HTMLDivElement {
        const div = document.createElement("div");
        if (str !== undefined) {
            div.innerText = str;
        }
        this.logdiv.appendChild(div);
        return div;
    },
    clear(): void {
        const div = this.logdiv;
        while (div.firstChild) {
            div.removeChild(div.firstChild);
        }
    }
}

let events: {[propName: string]: any} = {};

async function handleEvent(event): Promise<void> {
    if (!events[event.getId()]) {
        events[event.getId()] = {
            div: log.log(),
            event: event,
        };
    }
    const e = events[event.getId()];
    e.event = event;
    if (event.isBeingDecrypted()) {
        event.on("Event.decrypted", handleEvent);
        e.div.innerText = "Event decrypting...";
    } else if (event.getType() === "m.room.message") {
        e.div.innerText = `${event.getSender()}: ${event.getContent().body}`;
    } else if (event.isState()) {
        e.div.innerText = `${event.getType()} state event`;
    } else {
        e.div.innerText = `${event.getSender()}: ${event.getType()} event`;
    }
}

let loginButton: HTMLButtonElement;
window.addEventListener('DOMContentLoaded', async (event) => {
    log.init();
    await olm.init();
    loginButton = document.getElementById("login") as HTMLButtonElement;
    loginButton.onclick = async () => {
        loginButton.disabled = true;
        if (loggedIn) {
            client.stopClient();
            client.removeAllListeners();
            await client.logout();
            await client.clearStores();
            log.log("Logged out");
            loginButton.innerHTML = "Log in";
        } else {
            events = {};
            log.clear();
            const logdiv = log.log("Logging in...");

            // get the dehydrated device (if any) from the server
            const result = await client.loginWithRehydration("loginWithPassword", "@alice:example.com", "123456");
            console.log(result);

            // initialize the client with either the dehydrated device, or using the
            // normal login process
            dummyStore.reset();
            const opts: any = {
                baseUrl: "http://localhost:8008",
                accessToken: result.access_token,
                sessionStore: new (matrixcs as any).WebStorageSessionStore(dummyStore),
                cryptoCallbacks: cryptoCallbacks,
            };
            if (result._olm_account) {
                opts.deviceToImport = {
                    olmDevice: {
                        pickledAccount: result._olm_account.pickle("DEFAULT_KEY"),
                        sessions: [],
                        pickleKey: "DEFAULT_KEY",
                    },
                    userId: result.user_id,
                    deviceId: result.device_id,
                };
                result._olm_account.free();
            } else {
                opts.userId = result.user_id;
                opts.deviceId = result.device_id;
            }
            client = matrixcs.createClient(opts);
            await client.initCrypto();

            // display received events
            client.on("event", handleEvent);
            client.startClient({});

            // set up cross-signing and restore key backup
            await client.bootstrapSecretStorage();
            const {backupInfo} = await client.checkKeyBackup();
            client.enableKeyBackup(backupInfo); // FIXME: it doesn't seem to be uploading keys
            client.restoreKeyBackupWithCache(undefined, undefined, backupInfo);

            // upload a new dehydrated device
            await client.dehydrateDevice();

            loginButton.innerHTML = "Log out";
            logdiv.innerText = "Logged in";
        }
        loggedIn = !loggedIn;
        loginButton.disabled = false;
    };
});

// The following were copied-and-pasted from some matrix-js-sdk files, because
// TypeScript didn't want to import the files for some reason

// salt for HKDF, with 8 bytes of zeros
const zerosalt = new Uint8Array(32);

function encodeBase64(uint8Array) {
    return Buffer.from(uint8Array).toString("base64");
}

function decodeBase64(base64) {
    return Buffer.from(base64, "base64");
}

async function encryptAES(data, key, name, ivStr) {
    const subtleCrypto = window.crypto.subtle;
    let iv;
    if (ivStr) {
        iv = decodeBase64(ivStr);
    } else {
        iv = new Uint8Array(16);
        window.crypto.getRandomValues(iv);
    }

    // clear bit 63 of the IV to stop us hitting the 64-bit counter boundary
    // (which would mean we wouldn't be able to decrypt on Android). The loss
    // of a single bit of iv is a price we have to pay.
    iv[8] &= 0x7f;

    const [aesKey, hmacKey] = await deriveKeysBrowser(key, name);
    const encodedData = new TextEncoder().encode(data);

    const ciphertext = await subtleCrypto.encrypt(
        {
            name: "AES-CTR",
            counter: iv,
            length: 64,
        },
        aesKey,
        encodedData,
    );

    const hmac = await subtleCrypto.sign(
        'HMAC',
        hmacKey,
        ciphertext,
    );

    return {
        iv: encodeBase64(iv),
        ciphertext: encodeBase64(ciphertext),
        mac: encodeBase64(hmac),
    };
}

async function deriveKeysBrowser(key, name) {
    const subtleCrypto = window.crypto.subtle;
    const hkdfkey = await subtleCrypto.importKey(
        'raw',
        key,
        "HKDF",
        false,
        ["deriveBits"],
    );
    const keybits = await (subtleCrypto as any).deriveBits(
        {
            name: "HKDF",
            salt: zerosalt,
            info: (new TextEncoder().encode(name)),
            hash: "SHA-256",
        },
        hkdfkey,
        512,
    );

    const aesKey = keybits.slice(0, 32);
    const hmacKey = keybits.slice(32);

    const aesProm = (subtleCrypto as any).importKey(
        'raw',
        aesKey,
        {name: 'AES-CTR'},
        false,
        ['encrypt', 'decrypt'],
    );

    const hmacProm = (subtleCrypto as any).importKey(
        'raw',
        hmacKey,
        {
            name: 'HMAC',
            hash: {name: 'SHA-256'},
        },
        false,
        ['sign', 'verify'],
    );

    return await Promise.all([aesProm, hmacProm]);
}

async function deriveKey(password, salt, iterations, numBits = 256) {
    const subtleCrypto = window.crypto.subtle;
    const TextEncoder = window.TextEncoder;
    if (!subtleCrypto || !TextEncoder) {
        // TODO: Implement this for node
        throw new Error("Password-based backup is not avaiable on this platform");
    }

    const key = await subtleCrypto.importKey(
        'raw',
        new TextEncoder().encode(password),
        'PBKDF2',
        false,
        ['deriveBits'],
    );

    const keybits = await subtleCrypto.deriveBits(
        {
            name: 'PBKDF2',
            salt: new TextEncoder().encode(salt),
            iterations: iterations,
            hash: 'SHA-512',
        },
        key,
        numBits,
    );

    return new Uint8Array(keybits);
}
