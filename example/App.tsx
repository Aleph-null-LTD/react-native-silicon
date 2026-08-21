import { useState } from 'react';
import { ScrollView, Text, TouchableOpacity, View } from 'react-native';
//import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import {
    getCapabilities,
    generateKey,
    getKeyInfo,
    deleteKey,
    deleteAllKeys,
    listKeys,
    keyExists,
    validateKey,
    sign,
    SiliconError,
    SiliconErrorCode,
    getPubKey,
    generateSecureRandomBytes,
    attestKey,
    AttestResult,
    verify,
    getJwk,
    signJwt,
    generateDpopProof
} from 'react-native-silicon';

const styles = {
    header: {
        fontSize: 30,
        margin: 20,
    },
    buttonView: {
        flex: 1,
        margin: 20,
    },
    button: {
        backgroundColor: '#2a7fff',
        borderRadius: 8,
        paddingVertical: 12,
        paddingHorizontal: 16,
        alignItems: 'center' as const,
        justifyContent: 'center' as const,
    },
    buttonText: {
        color: '#ffffff',
        fontSize: 16,
        fontWeight: '600' as const,
    },
};

const keyAlias = 'silicon.testkey';

export default function App() {

    //throw new Error("test")
    const [capabilities, setCapabilities] = useState("Click the button to get the capabilities");
    const onGetDeviceCaps = async (): Promise<void> => {
        try {
            const caps = await getCapabilities();
            setCapabilities(JSON.stringify(caps, undefined, 4));
        } catch (error) {
            if (error instanceof SiliconError) {
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [randBytesStr, setRandBytesStr] = useState("Click the button to get secure random bytes");
    const onGenRandBytes = async (): Promise<void> => {
        try {
            const srb = await generateSecureRandomBytes(32);
            setRandBytesStr(`Secure Random Bytes: \n${srb}`)
        } catch (error) {
            if (error instanceof SiliconError) {
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [genKeyStr, setGenKeyStr] = useState("Click the button to generate a key");
    const onGenKey = async (): Promise<void> => {
        console.log("Generating key");
        try {
            const attestChallenge = await generateSecureRandomBytes(32);

            await generateKey(
                keyAlias,
                {
                    attestChallenge: attestChallenge,
                    userAuth: {
                        require: true,
                        policy: 'BIOMETRICS_ONLY',
                        invalidateOnEnrollment: false,
                        timeout: 30
                    },
                    android: {
                        hardwarePolicy: 'PREFER_STRONGBOX'
                    },
                    ios: {
                        algorithm: 'EC_P256',
                        //signaturePaddingAlgorithm: 'PSS',
                        digests: ['SHA256'],
                        hardwarePolicy: 'REQUIRE_SECURE_ENCLAVE'
                    }
                }
            );
            setGenKeyStr(`Key generated ${new Date().toISOString()}`);
        } catch (error) {
            if (error instanceof SiliconError) {
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [info, setInfo] = useState("Click the button to get the key info");
    const onGetKeyInfo = async (): Promise<void> => {
        try {
            const inf = await getKeyInfo(keyAlias);
            setInfo(JSON.stringify(inf, undefined, 4));
        } catch (error) {
            if (error instanceof SiliconError) {
                if (error.code == SiliconErrorCode.KEY_NOT_FOUND) {
                    setInfo("Key Not Found");
                } else {
                    console.error(error.serialize(4));
                }
            } else {
                console.error(error);
            }
        }
    }

    const onDelKey = async (): Promise<void> => {
        console.log("Deleting key");
        try {
            await deleteKey(keyAlias);
            console.log("Key deleted")
        } catch (error) {
            if (error instanceof SiliconError) {
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const onDeleteAllKeys = async (): Promise<void> => {
        console.log("Deleting all keys");
        try {
            const delKeyCount = await deleteAllKeys();
            console.log(`${delKeyCount} Keys deleted`)
        } catch (error) {
            if (error instanceof SiliconError) {
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [keyExistsStr, setKeyExistsStr] = useState("Click the button to check if key exists");
    const onCheckIfKeyExists = async (): Promise<void> => {
        try {
            const doesKeyExist = await keyExists(keyAlias);

            if (doesKeyExist) {
                setKeyExistsStr("Key exists");
            } else {
                setKeyExistsStr("Key does not exist");
            }

        } catch (error) {
            if (error instanceof SiliconError) {
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [keyList, setKeyList] = useState("Click the button to list keys");
    const onListKeys = async (): Promise<void> => {
        try {
            const kList = await listKeys();
            let kStr = "No keys found";

            if (kList.length > 0) kStr = kList.join(",");

            setKeyList(kStr);

        } catch (error) {
            if (error instanceof SiliconError) {
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [keyValidity, setKeyValidity] = useState("Click button to get key validity")
    const onValidateKey = async () => {
        try {
            const keyVal = await validateKey(keyAlias);

            setKeyValidity(`Key Validity: ${keyVal}`);

        } catch (error) {
            if (error instanceof SiliconError) {
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [attestCerts, setAttestCerts] = useState("Click button to get attest certs for key")
    const onAttestKey = async () => {
        try {
            const attestResult = await attestKey(keyAlias, "STRING", "PEM");

            setAttestCerts(`Attest Result: \n${JSON.stringify(attestResult, undefined, 4)}`);

        } catch (error) {
            if (error instanceof SiliconError) {
                if (error.code == SiliconErrorCode.KEY_NOT_FOUND) {
                    setAttestCerts("Key Not Found");
                } else {
                    console.error(error.serialize(4));
                }
            } else {
                console.error(error);
            }
        }
    }

    const [pubKeyStr, setPubKeyStr] = useState("Click button to get the public key")
    const onGetPubKey = async () => {
        try {
            const pubKey = await getPubKey(keyAlias, 'PEM');

            const str = `Public Key:\n${pubKey}`;
            setPubKeyStr(str);
            console.log(str);

        } catch (error) {
            if (error instanceof SiliconError) {
                if (error.code == SiliconErrorCode.KEY_NOT_FOUND) {
                    setPubKeyStr("Key Not Found");
                } else {
                    console.error(error.serialize(4));
                }
            } else {
                console.error(error);
            }
        }
    }

    const [signature, setSignature] = useState("Click the button to sign data");
    const onSign = async (): Promise<void> => {
        console.log("Signing");
        try {
            const s = await sign(keyAlias, new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF]), { encoding: 'B64URL' });
            setSignature(s);
        } catch (error) {
            if (error instanceof SiliconError) {
                if (error.code == SiliconErrorCode.KEY_NOT_FOUND) {
                    setSignature("Key Not Found");
                } else {
                    console.error(error.serialize(4));
                }
            } else {
                console.error(error);
            }
        }
    }

    const [verifiedStr, setVerifiedStr] = useState("Click the button to verify signature");
    const onVerify = async (): Promise<void> => {
        console.log("Verifying");
        try {
            const isVerified = await verify(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0xFF]), signature, { alias: keyAlias });

            if (isVerified) {
                setVerifiedStr("Signature is good");
            } else {
                setVerifiedStr("Signature is bad");
            }

        } catch (error) {
            if (error instanceof SiliconError) {
                if (error.code == SiliconErrorCode.KEY_NOT_FOUND) {
                    setVerifiedStr("Key Not Found");
                } else {
                    console.error(error.serialize(4));
                }
            } else {
                console.error(error);
            }
        }
    }

    const [jwkStr, setJwkStr] = useState("Click the button to get the JWK");
    const onGetJwk = async (): Promise<void> => {
        try {
            const jwk = await getJwk(keyAlias);

            console.log(`JWK: ${JSON.stringify(jwk)}`);
            setJwkStr(JSON.stringify(jwk, undefined, 4));

        } catch (error) {
            if (error instanceof SiliconError) {
                if (error.code === SiliconErrorCode.KEY_NOT_FOUND) {
                    setJwkStr("Key not found");
                }
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [jwtStr, setJwtStr] = useState("Click the button to get the JWK");
    const onSignJwt = async (): Promise<void> => {
        try {
            const jwt = await signJwt(
                keyAlias,
                {
                    typ: 'JWT'
                },
                {
                    iat: Math.floor(Date.now() / 1000),
                    jti: await generateSecureRandomBytes(16, "B64URL")
                }
            );

            console.log(`JWT: ${jwt}`);
            setJwtStr(jwt);

        } catch (error) {
            if (error instanceof SiliconError) {
                if (error.code === SiliconErrorCode.KEY_NOT_FOUND) {
                    setJwtStr("Key not found");
                }
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    const [dpopStr, setDpopStr] = useState("Click the button to get the DPoP proof");
    const onGenerateDpop = async (): Promise<void> => {
        try {
            const jwt = await generateDpopProof(
                keyAlias, 
                {
                    htm: 'POST',
                    htu: 'https://some.random/endpoint/here',
                    jti: await generateSecureRandomBytes(16, "B64URL"),
                    nonce: await generateSecureRandomBytes(24, "B64URL"),
                }
            );

            console.log(`DPoP: ${jwt}`);
            setDpopStr(jwt);

        } catch (error) {
            if (error instanceof SiliconError) {
                if (error.code === SiliconErrorCode.KEY_NOT_FOUND) {
                    setDpopStr("Key not found");
                }
                console.error(error.serialize(4));
            } else {
                console.error(error);
            }
        }
    }

    return (
        //<SafeAreaProvider>
            //<SafeAreaView>
                <ScrollView>
                    <View style={{ marginBottom: 400 }}>
                        <Text style={styles.header}>react-native-silicon</Text>
                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onGetDeviceCaps}>
                                <Text style={styles.buttonText}>Get Capabilities</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{capabilities}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onGenRandBytes}>
                                <Text style={styles.buttonText}>Gen Secure Random Bytes</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{randBytesStr}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onGenKey}>
                                <Text style={styles.buttonText}>Gen Key</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{genKeyStr}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onDelKey}>
                                <Text style={styles.buttonText}>Del Key</Text>
                            </TouchableOpacity>
                        </View>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onDeleteAllKeys}>
                                <Text style={styles.buttonText}>Del All Keys</Text>
                            </TouchableOpacity>
                        </View>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onGetKeyInfo}>
                                <Text style={styles.buttonText}>Get Key Info</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{info}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onCheckIfKeyExists}>
                                <Text style={styles.buttonText}>Does Key Exist</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "center" }}>{keyExistsStr}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onListKeys}>
                                <Text style={styles.buttonText}>List Keys</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "center" }}>{keyList}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onValidateKey}>
                                <Text style={styles.buttonText}>Validate Key</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "center" }}>{keyValidity}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onAttestKey}>
                                <Text style={styles.buttonText}>Attest Key</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{attestCerts}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onGetPubKey}>
                                <Text style={styles.buttonText}>Get Public Key</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{pubKeyStr}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onSign}>
                                <Text style={styles.buttonText}>Sign Some Data</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "center" }}>{signature}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onVerify}>
                                <Text style={styles.buttonText}>Verify Signature</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "center" }}>{verifiedStr}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onGetJwk}>
                                <Text style={styles.buttonText}>Get JWK</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{jwkStr}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onSignJwt}>
                                <Text style={styles.buttonText}>Sign JWT</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{jwtStr}</Text>

                        <View style={styles.buttonView}>
                            <TouchableOpacity style={styles.button} onPress={onGenerateDpop}>
                                <Text style={styles.buttonText}>Gen DPoP</Text>
                            </TouchableOpacity>
                        </View>
                        <Text style={{ textAlign: "left", paddingLeft: 20 }}>{dpopStr}</Text>

                    </View>
                </ScrollView>
            //</SafeAreaView>
        //</SafeAreaProvider>
    );
}

