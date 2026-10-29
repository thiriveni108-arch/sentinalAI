import type { Metadata } from "next";
import { ResponseAutomation } from "@/components/shield/response-automation";

export const metadata:Metadata={title:"Response Automation"};
export default function ResponseAutomationPage(){return <ResponseAutomation/>}
