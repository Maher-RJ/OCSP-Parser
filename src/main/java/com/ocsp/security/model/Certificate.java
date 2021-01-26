package com.ocsp.security.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Certificate {

    private String issuerNameHash;
    private String issuerKeyHash;
    private String serialNumber;

    @Override
    public String toString() {
        return "Certificate [\n\t\t\t\t Issuer Name Hash=" + issuerNameHash + ",\n\t\t\t\t Issuer Key Hash=" + issuerKeyHash + ",\n\t\t\t\t SerialNumber="
                + serialNumber + "\n\t\t\t]";
    }
}
