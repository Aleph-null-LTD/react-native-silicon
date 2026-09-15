
export type BridgeResult<T> = { 
    success: true,
    data: T 
} | { 
    success: false,
    errorCode: string,
    errorMessage: string,
    nativeStack: string | null
};
