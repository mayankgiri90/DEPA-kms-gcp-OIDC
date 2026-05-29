export interface IKeyRotationPolicy {
    rotation_interval_seconds: number;
    /**
     * Grace period (seconds). Also used as the delay before a newly created key
     * is exposed as "latest" on public-key endpoints (listpubkeys, pubkey): set
     * >= private key client cache TTL (e.g. 7200 for 2 hours) so public key
     * clients only see a key after private key clients have had time to cache it.
     */
    grace_period_seconds: number;
}
