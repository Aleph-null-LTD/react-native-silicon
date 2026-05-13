export interface SignOpts {
    /**
     * The encoding to use for the signature.
     * 
     * default - B64_URL
     */
    encoding: 'B64_URL' | 'B64';
    
    /**
     * The algorithm to use for the signature
     * 
     * default - SHA256
     */
    algorithm: 'SHA256';
};
