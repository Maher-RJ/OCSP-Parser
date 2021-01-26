package com.ocsp.security.model;

import lombok.Getter;
import lombok.Setter;
import java.util.Date;
import java.util.List;

@Getter
@Setter
public class OCSPResponseData {

    private String status;
    private int version;
    private Date producedAt;
    private String responderId;
    private List<Response> responses;

    @Override
    public String toString() {
        return "OCSPResponseData [\n\tResponse Status=" + status + ",\n\t Version=" + version + ",\n\t Produced At=" + producedAt
                + ",\n\t Responder Id=" + responderId + ",\n\t Responses=" + responses + "\n]";
    }

}
