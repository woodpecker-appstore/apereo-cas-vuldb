package me.gv7;

import static org.junit.Assert.assertTrue;

import me.gv7.woodpecker.plugin.CasCommonUtils;
import me.gv7.woodpecker.plugin.payloads.CasPayloadGenerate;
import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest 
{
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue() {
        String urldns = CasCommonUtils.generate("CommonsCollections4", "TomcatFilterWebshell");
    }
}
