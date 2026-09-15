
const PLUS_REGEX = /\+/g;
const SLASH_REGEX = /\//g;
const EQUALS_REGEX = /=+$/;

export function objectToBase64Url(obj: object): string {
    // Stringify the object to JSON
    const jsonStr = JSON.stringify(obj);

    let standardBase64;

    // Safely encode UTF-8 characters and convert to standard Base64.
    // Check if TextEncoder is present and use that if available, if not fallback to the legacy supported path
    if (typeof TextEncoder !== 'undefined') {
      const bytes = new TextEncoder().encode(jsonStr);
    
      // Convert Uint8Array to a binary string
      const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
    
      standardBase64 = btoa(binString);
    } else {
      // Legacy Path: Fallback to the encodeURIComponent trick

      const utf8Str = unescape(encodeURIComponent(jsonStr));
    
      standardBase64 = btoa(utf8Str);
    }

    // Convert to strict Base64URL (swap chars, strip padding =)
    return standardBase64
      .replace(PLUS_REGEX, '-')
      .replace(SLASH_REGEX, '_')
      .replace(EQUALS_REGEX, '');
}