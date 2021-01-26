package com.ocsp.security.model;

import lombok.Getter;
import lombok.Setter;
import java.util.Date;

@Getter
@Setter
public class Response {

    private Date thisUpdate;
    private Date nextUpdate;
    private Certificate certificate;
    private String certStatus;

    @Override
    public String toString() {
        return "\n\t\tResponse [\n\t\t\tThis Update=" + thisUpdate + ",\n\t\t\t Next Update=" + nextUpdate + ",\n\t\t\t" + certificate
                + ",\n\t\t\t Cert Status=" + certStatus + "\n\t]";
    }

}

