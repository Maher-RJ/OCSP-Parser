package com.ocsp.security.parser;


import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.ocsp.security.model.Certificate;
import com.ocsp.security.model.OCSPResponseData;
import com.ocsp.security.model.Response;
import lombok.val;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;


public class OCSPParser {

    private static final Logger logger = Logger.getLogger(OCSPParser.class.getCanonicalName());

    private static OCSPResponseData ocspResponseData = new OCSPResponseData();
    private static List<Response> responses = new ArrayList<Response>();
    private static Certificate certificate = new Certificate();

    /*
     * Get OCSP Response as byte[] input and returns the Parsed Response
     */
    public OCSPResponseData parseResponse(byte[] ocspResponse) {
        try {
            // OCSP response is parsed into BouncyCastle's OCSPResp Object
            val ocspResp = new OCSPResp(ocspResponse);

            val ocspResponseObject = ocspResp.getResponseObject();
            if ((ocspResponseObject instanceof BasicOCSPResp)) {
                val basicOcspResponse = (BasicOCSPResp) ocspResp.getResponseObject();

                ocspResponseData.setStatus(getOCSPStatus(ocspResp.getStatus()));
                ocspResponseData.setVersion(basicOcspResponse.getVersion());
                ocspResponseData.setProducedAt(basicOcspResponse.getProducedAt());
                ocspResponseData.setResponderId(
                        basicOcspResponse.getResponderId().toASN1Object().getDERObject().toString().substring(3));

                // One OCSP Response can contain multiple Certificate Response, hence get all
                SingleResp[] singleResps = basicOcspResponse.getResponses();
                for (SingleResp singleResp : singleResps) {
                    CertificateStatus status = (CertificateStatus) singleResp.getCertStatus();
                    certificate.setIssuerKeyHash(singleResp.getCertID().getIssuerKeyHash().toString());
                    certificate.setIssuerNameHash(singleResp.getCertID().getIssuerNameHash().toString());
                    certificate.setSerialNumber(String.valueOf(singleResp.getCertID().getSerialNumber()));

                    Response resp = new Response();
                    resp.setCertStatus(getCertStatus(status));
                    resp.setThisUpdate(singleResp.getThisUpdate());
                    resp.setNextUpdate(singleResp.getNextUpdate());
                    resp.setCertificate(certificate);
                    responses.add(resp);
                }

                ocspResponseData.setResponses(responses);
                System.out.println(ocspResponseData);
                return ocspResponseData;
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, e.getMessage(), e.getCause());
            return null;
        }
        return null;

    }

    /*
     * Returns Status based on value from OCSP Response
     */
    private String getOCSPStatus(int ocspResponseStatus) {
        String status;
        switch (ocspResponseStatus) {
            case 0 -> status = "Successful";
            case 1 -> status = "MalformedRequest";
            case 2 -> status = "InternalError";
            case 3 -> status = "TryLater";
            case 5 -> status = "sigRequired";
            default -> status = "unauthorized";
        }
        return status;
    }

    /*
     * Returns Certificate Status
     */
    private String getCertStatus(Object certStatus) {
        String status;
        if (certStatus == CertificateStatus.GOOD) {
            status = "Good";
        } else if (certStatus instanceof RevokedStatus) {
            status = "Revoked";
        } else {
            status = "Unknown";
        }
        return status;
    }

}

