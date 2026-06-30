use serde::{Deserialize, Serialize};

// ── PFCP (N4 Interface — 3GPP TS 29.244) ──────────────────────────────────────

pub const PFCP_PORT: u16 = 8805;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpMessage {
    pub version: u8,
    pub message_type: PfcpMessageType,
    pub length: u16,
    pub seid: Option<u64>,
    pub sequence_number: u32,
    pub ies: Vec<PfcpIe>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PfcpMessageType {
    HeartbeatRequest = 1,
    HeartbeatResponse = 2,
    AssociationSetupRequest = 5,
    AssociationSetupResponse = 6,
    AssociationUpdateRequest = 7,
    AssociationUpdateResponse = 8,
    AssociationReleaseRequest = 9,
    AssociationReleaseResponse = 10,
    SessionEstablishmentRequest = 50,
    SessionEstablishmentResponse = 51,
    SessionModificationRequest = 52,
    SessionModificationResponse = 53,
    SessionDeletionRequest = 54,
    SessionDeletionResponse = 55,
    SessionReportRequest = 56,
    SessionReportResponse = 57,
    Unknown(u8),
}

impl From<u8> for PfcpMessageType {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::HeartbeatRequest,
            2 => Self::HeartbeatResponse,
            5 => Self::AssociationSetupRequest,
            6 => Self::AssociationSetupResponse,
            7 => Self::AssociationUpdateRequest,
            8 => Self::AssociationUpdateResponse,
            9 => Self::AssociationReleaseRequest,
            10 => Self::AssociationReleaseResponse,
            50 => Self::SessionEstablishmentRequest,
            51 => Self::SessionEstablishmentResponse,
            52 => Self::SessionModificationRequest,
            53 => Self::SessionModificationResponse,
            54 => Self::SessionDeletionRequest,
            55 => Self::SessionDeletionResponse,
            56 => Self::SessionReportRequest,
            57 => Self::SessionReportResponse,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PfcpIe {
    FSeid {
        seid: u64,
        ipv4: Option<u32>,
        ipv6: Option<[u8; 16]>,
    },
    Pdr {
        rule_id: u16,
        precedence: u32,
        pdi: Option<PfcpPdi>,
    },
    Far {
        far_id: u32,
        apply_action: u8,
        forwarding_params: Option<ForwardingParams>,
    },
    Qer {
        qer_id: u32,
        gate_status: u8,
        mbr_ul: u64,
        mbr_dl: u64,
    },
    Urr {
        urr_id: u32,
        measurement_method: u8,
        reporting_triggers: u32,
    },
    NodeId {
        node_type: u8,
        value: Vec<u8>,
    },
    Cause(u8),
    RecoveryTimestamp(u32),
    Unknown {
        ie_type: u16,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfcpPdi {
    pub source_interface: u8,
    pub network_instance: Option<String>,
    pub ue_ip: Option<u32>,
    pub teid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardingParams {
    pub destination_interface: u8,
    pub network_instance: Option<String>,
    pub outer_header_creation: Option<OuterHeaderCreation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OuterHeaderCreation {
    pub description: u16,
    pub teid: u32,
    pub ipv4: Option<u32>,
}

pub fn parse_pfcp(data: &[u8]) -> Option<PfcpMessage> {
    if data.len() < 8 {
        return None;
    }

    let flags = data[0];
    let version = (flags >> 5) & 0x07;
    if version != 1 {
        return None;
    }

    let has_seid = (flags & 0x01) != 0;
    let message_type = PfcpMessageType::from(data[1]);
    let length = u16::from_be_bytes([data[2], data[3]]);

    let (seid, seq_offset) = if has_seid {
        if data.len() < 16 {
            return None;
        }
        let seid = u64::from_be_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);
        (Some(seid), 12)
    } else {
        (None, 4)
    };

    if data.len() < seq_offset + 4 {
        return None;
    }

    let sequence_number = u32::from_be_bytes([
        0,
        data[seq_offset],
        data[seq_offset + 1],
        data[seq_offset + 2],
    ]);

    let ie_start = seq_offset + 4;
    let ies = parse_pfcp_ies(&data[ie_start..]);

    Some(PfcpMessage {
        version,
        message_type,
        length,
        seid,
        sequence_number,
        ies,
    })
}

fn parse_pfcp_ies(mut data: &[u8]) -> Vec<PfcpIe> {
    let mut ies = Vec::new();

    while data.len() >= 4 {
        let ie_type = u16::from_be_bytes([data[0], data[1]]);
        let ie_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + ie_len {
            break;
        }

        let ie_data = &data[4..4 + ie_len];
        let ie = match ie_type {
            57 => parse_pfcp_fseid(ie_data),
            1 => parse_pfcp_pdr(ie_data),
            3 => parse_pfcp_far(ie_data),
            54 => parse_pfcp_qer(ie_data),
            55 => parse_pfcp_urr(ie_data),
            60 => PfcpIe::NodeId {
                node_type: ie_data.first().copied().unwrap_or(0),
                value: ie_data.get(1..).unwrap_or_default().to_vec(),
            },
            19 => PfcpIe::Cause(ie_data.first().copied().unwrap_or(0)),
            96 => PfcpIe::RecoveryTimestamp(if ie_data.len() >= 4 {
                u32::from_be_bytes([ie_data[0], ie_data[1], ie_data[2], ie_data[3]])
            } else {
                0
            }),
            _ => PfcpIe::Unknown {
                ie_type,
                data: ie_data.to_vec(),
            },
        };

        ies.push(ie);
        data = &data[4 + ie_len..];
    }

    ies
}

fn parse_pfcp_fseid(data: &[u8]) -> PfcpIe {
    if data.len() < 9 {
        return PfcpIe::Unknown {
            ie_type: 57,
            data: data.to_vec(),
        };
    }
    let flags = data[0];
    let seid = u64::from_be_bytes([
        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
    ]);
    let ipv4 = if (flags & 0x02) != 0 && data.len() >= 13 {
        Some(u32::from_be_bytes([data[9], data[10], data[11], data[12]]))
    } else {
        None
    };
    PfcpIe::FSeid {
        seid,
        ipv4,
        ipv6: None,
    }
}

fn parse_pfcp_pdr(data: &[u8]) -> PfcpIe {
    if data.len() < 6 {
        return PfcpIe::Unknown {
            ie_type: 1,
            data: data.to_vec(),
        };
    }
    let rule_id = u16::from_be_bytes([data[0], data[1]]);
    let precedence = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
    PfcpIe::Pdr {
        rule_id,
        precedence,
        pdi: None,
    }
}

fn parse_pfcp_far(data: &[u8]) -> PfcpIe {
    if data.len() < 5 {
        return PfcpIe::Unknown {
            ie_type: 3,
            data: data.to_vec(),
        };
    }
    let far_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let apply_action = data[4];
    PfcpIe::Far {
        far_id,
        apply_action,
        forwarding_params: None,
    }
}

fn parse_pfcp_qer(data: &[u8]) -> PfcpIe {
    if data.len() < 5 {
        return PfcpIe::Unknown {
            ie_type: 54,
            data: data.to_vec(),
        };
    }
    let qer_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let gate_status = data[4];
    PfcpIe::Qer {
        qer_id,
        gate_status,
        mbr_ul: 0,
        mbr_dl: 0,
    }
}

fn parse_pfcp_urr(data: &[u8]) -> PfcpIe {
    if data.len() < 5 {
        return PfcpIe::Unknown {
            ie_type: 55,
            data: data.to_vec(),
        };
    }
    let urr_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let measurement_method = data[4];
    PfcpIe::Urr {
        urr_id,
        measurement_method,
        reporting_triggers: 0,
    }
}

// ── NGAP (N2 Interface — 3GPP TS 38.413) ──────────────────────────────────────

pub const NGAP_PORT: u16 = 38412;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NgapMessage {
    pub procedure_code: NgapProcedureCode,
    pub criticality: Criticality,
    pub message_class: NgapMessageClass,
    pub amf_ue_ngap_id: Option<u64>,
    pub ran_ue_ngap_id: Option<u32>,
    pub ies: Vec<NgapIe>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NgapProcedureCode {
    InitialUEMessage,
    UplinkNASTransport,
    DownlinkNASTransport,
    InitialContextSetup,
    UEContextRelease,
    UEContextReleaseCommand,
    HandoverRequired,
    HandoverCommand,
    HandoverNotify,
    HandoverPreparation,
    HandoverCancel,
    PathSwitchRequest,
    PDUSessionResourceSetup,
    PDUSessionResourceRelease,
    PDUSessionResourceModify,
    Paging,
    NGSetup,
    NGReset,
    ErrorIndication,
    Unknown(u8),
}

impl From<u8> for NgapProcedureCode {
    fn from(val: u8) -> Self {
        match val {
            15 => Self::InitialUEMessage,
            46 => Self::UplinkNASTransport,
            4 => Self::DownlinkNASTransport,
            14 => Self::InitialContextSetup,
            41 => Self::UEContextRelease,
            42 => Self::UEContextReleaseCommand,
            1 => Self::HandoverRequired,
            2 => Self::HandoverCommand,
            11 => Self::HandoverNotify,
            0 => Self::HandoverPreparation,
            3 => Self::HandoverCancel,
            12 => Self::PathSwitchRequest,
            29 => Self::PDUSessionResourceSetup,
            30 => Self::PDUSessionResourceRelease,
            31 => Self::PDUSessionResourceModify,
            36 => Self::Paging,
            21 => Self::NGSetup,
            20 => Self::NGReset,
            19 => Self::ErrorIndication,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Criticality {
    Reject,
    Ignore,
    Notify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NgapMessageClass {
    InitiatingMessage,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NgapIe {
    AmfUeNgapId(u64),
    RanUeNgapId(u32),
    NasPdu(Vec<u8>),
    Cause {
        group: u8,
        value: u8,
    },
    UserLocationInfo {
        nr_cgi: Option<NrCgi>,
        tai: Option<Tai>,
    },
    SourceToTargetContainer(Vec<u8>),
    TargetToSourceContainer(Vec<u8>),
    PduSessionResourceSetupList(Vec<PduSessionItem>),
    AllowedNssai(Vec<SNssai>),
    Guami {
        plmn: [u8; 3],
        amf_region: u8,
        amf_set: u16,
        amf_pointer: u8,
    },
    FiveGSTmsi {
        amf_set: u16,
        amf_pointer: u8,
        tmsi: u32,
    },
    Unknown {
        id: u16,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NrCgi {
    pub plmn: [u8; 3],
    pub cell_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tai {
    pub plmn: [u8; 3],
    pub tac: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PduSessionItem {
    pub session_id: u8,
    pub s_nssai: SNssai,
    pub transfer: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNssai {
    pub sst: u8,
    pub sd: Option<u32>,
}

pub fn parse_ngap(data: &[u8]) -> Option<NgapMessage> {
    // NGAP runs over SCTP — assume SCTP payload has been extracted
    // NGAP PDU is ASN.1 PER encoded; we parse the outer structure
    if data.len() < 4 {
        return None;
    }

    // Byte 0: message class (InitiatingMessage=0, SuccessfulOutcome=1, UnsuccessfulOutcome=2)
    let message_class = match data[0] & 0x60 {
        0x00 => NgapMessageClass::InitiatingMessage,
        0x20 => NgapMessageClass::SuccessfulOutcome,
        0x40 => NgapMessageClass::UnsuccessfulOutcome,
        _ => return None,
    };

    let procedure_code = NgapProcedureCode::from(data[1]);

    let criticality = match (data[2] >> 6) & 0x03 {
        0 => Criticality::Reject,
        1 => Criticality::Ignore,
        _ => Criticality::Notify,
    };

    let ie_offset = 4;
    let (amf_ue_ngap_id, ran_ue_ngap_id, ies) = parse_ngap_ies(&data[ie_offset..]);

    Some(NgapMessage {
        procedure_code,
        criticality,
        message_class,
        amf_ue_ngap_id,
        ran_ue_ngap_id,
        ies,
    })
}

fn parse_ngap_ies(mut data: &[u8]) -> (Option<u64>, Option<u32>, Vec<NgapIe>) {
    let mut ies = Vec::new();
    let mut amf_id = None;
    let mut ran_id = None;

    while data.len() >= 4 {
        let ie_id = u16::from_be_bytes([data[0], data[1]]);
        let _criticality = data[2];
        let ie_len = data[3] as usize;

        if data.len() < 4 + ie_len {
            break;
        }

        let ie_data = &data[4..4 + ie_len];

        let ie = match ie_id {
            10 => {
                if ie_data.len() >= 8 {
                    let id = u64::from_be_bytes([
                        ie_data[0], ie_data[1], ie_data[2], ie_data[3], ie_data[4], ie_data[5],
                        ie_data[6], ie_data[7],
                    ]);
                    amf_id = Some(id);
                    NgapIe::AmfUeNgapId(id)
                } else {
                    NgapIe::Unknown {
                        id: ie_id,
                        data: ie_data.to_vec(),
                    }
                }
            }
            85 => {
                if ie_data.len() >= 4 {
                    let id = u32::from_be_bytes([ie_data[0], ie_data[1], ie_data[2], ie_data[3]]);
                    ran_id = Some(id);
                    NgapIe::RanUeNgapId(id)
                } else {
                    NgapIe::Unknown {
                        id: ie_id,
                        data: ie_data.to_vec(),
                    }
                }
            }
            38 => NgapIe::NasPdu(ie_data.to_vec()),
            15 => {
                if ie_data.len() >= 2 {
                    NgapIe::Cause {
                        group: ie_data[0],
                        value: ie_data[1],
                    }
                } else {
                    NgapIe::Unknown {
                        id: ie_id,
                        data: ie_data.to_vec(),
                    }
                }
            }
            104 => NgapIe::SourceToTargetContainer(ie_data.to_vec()),
            105 => NgapIe::TargetToSourceContainer(ie_data.to_vec()),
            _ => NgapIe::Unknown {
                id: ie_id,
                data: ie_data.to_vec(),
            },
        };

        ies.push(ie);
        data = &data[4 + ie_len..];
    }

    (amf_id, ran_id, ies)
}

// ── XnAP (Xn Interface — 3GPP TS 38.423) ──────────────────────────────────────

pub const XNAP_PORT: u16 = 38422;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XnApMessage {
    pub procedure_code: XnApProcedureCode,
    pub criticality: Criticality,
    pub message_class: XnApMessageClass,
    pub source_ng_ran_node_ue_xnap_id: Option<u32>,
    pub target_ng_ran_node_ue_xnap_id: Option<u32>,
    pub ies: Vec<XnApIe>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XnApProcedureCode {
    HandoverPreparation,
    HandoverCancel,
    RetrieveUEContext,
    SNStatusTransfer,
    UEContextRelease,
    RANPaging,
    XnSetup,
    XnReset,
    SecondaryRATDataUsageReport,
    ActivityNotification,
    Unknown(u8),
}

impl From<u8> for XnApProcedureCode {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::HandoverPreparation,
            1 => Self::HandoverCancel,
            2 => Self::RetrieveUEContext,
            3 => Self::SNStatusTransfer,
            4 => Self::UEContextRelease,
            7 => Self::RANPaging,
            12 => Self::XnSetup,
            14 => Self::XnReset,
            16 => Self::SecondaryRATDataUsageReport,
            20 => Self::ActivityNotification,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XnApMessageClass {
    InitiatingMessage,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XnApIe {
    SourceNgRanNodeUeXnApId(u32),
    TargetNgRanNodeUeXnApId(u32),
    Cause {
        group: u8,
        value: u8,
    },
    TargetCellGlobalId {
        plmn: [u8; 3],
        cell_id: u64,
    },
    UeContextInfoHoReq(Vec<u8>),
    SnStatusTransfer {
        drb_id: u8,
        pdcp_sn_ul: u32,
        pdcp_sn_dl: u32,
        hfn_ul: u32,
        hfn_dl: u32,
    },
    PduSessionResourcesAdmitted(Vec<XnApPduSession>),
    UeSecurityCapabilities {
        nr_ea: u16,
        nr_ia: u16,
        e_utra_ea: u16,
        e_utra_ia: u16,
    },
    Unknown {
        id: u16,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XnApPduSession {
    pub session_id: u8,
    pub s_nssai: SNssai,
    pub qos_flow_list: Vec<QosFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlow {
    pub qfi: u8,
    pub fiveqi: u8,
    pub priority: u8,
}

pub fn parse_xnap(data: &[u8]) -> Option<XnApMessage> {
    // XnAP runs over SCTP — assume SCTP payload extracted
    // XnAP PDU is ASN.1 PER encoded; we parse the outer wrapper
    if data.len() < 4 {
        return None;
    }

    let message_class = match data[0] & 0x60 {
        0x00 => XnApMessageClass::InitiatingMessage,
        0x20 => XnApMessageClass::SuccessfulOutcome,
        0x40 => XnApMessageClass::UnsuccessfulOutcome,
        _ => return None,
    };

    let procedure_code = XnApProcedureCode::from(data[1]);

    let criticality = match (data[2] >> 6) & 0x03 {
        0 => Criticality::Reject,
        1 => Criticality::Ignore,
        _ => Criticality::Notify,
    };

    let ie_offset = 4;
    let (source_id, target_id, ies) = parse_xnap_ies(&data[ie_offset..]);

    Some(XnApMessage {
        procedure_code,
        criticality,
        message_class,
        source_ng_ran_node_ue_xnap_id: source_id,
        target_ng_ran_node_ue_xnap_id: target_id,
        ies,
    })
}

fn parse_xnap_ies(mut data: &[u8]) -> (Option<u32>, Option<u32>, Vec<XnApIe>) {
    let mut ies = Vec::new();
    let mut source_id = None;
    let mut target_id = None;

    while data.len() >= 4 {
        let ie_id = u16::from_be_bytes([data[0], data[1]]);
        let _criticality = data[2];
        let ie_len = data[3] as usize;

        if data.len() < 4 + ie_len {
            break;
        }

        let ie_data = &data[4..4 + ie_len];

        let ie = match ie_id {
            1 => {
                if ie_data.len() >= 4 {
                    let id = u32::from_be_bytes([ie_data[0], ie_data[1], ie_data[2], ie_data[3]]);
                    source_id = Some(id);
                    XnApIe::SourceNgRanNodeUeXnApId(id)
                } else {
                    XnApIe::Unknown {
                        id: ie_id,
                        data: ie_data.to_vec(),
                    }
                }
            }
            2 => {
                if ie_data.len() >= 4 {
                    let id = u32::from_be_bytes([ie_data[0], ie_data[1], ie_data[2], ie_data[3]]);
                    target_id = Some(id);
                    XnApIe::TargetNgRanNodeUeXnApId(id)
                } else {
                    XnApIe::Unknown {
                        id: ie_id,
                        data: ie_data.to_vec(),
                    }
                }
            }
            13 => {
                if ie_data.len() >= 2 {
                    XnApIe::Cause {
                        group: ie_data[0],
                        value: ie_data[1],
                    }
                } else {
                    XnApIe::Unknown {
                        id: ie_id,
                        data: ie_data.to_vec(),
                    }
                }
            }
            21 => {
                if ie_data.len() >= 17 {
                    XnApIe::SnStatusTransfer {
                        drb_id: ie_data[0],
                        pdcp_sn_ul: u32::from_be_bytes([
                            ie_data[1], ie_data[2], ie_data[3], ie_data[4],
                        ]),
                        pdcp_sn_dl: u32::from_be_bytes([
                            ie_data[5], ie_data[6], ie_data[7], ie_data[8],
                        ]),
                        hfn_ul: u32::from_be_bytes([
                            ie_data[9],
                            ie_data[10],
                            ie_data[11],
                            ie_data[12],
                        ]),
                        hfn_dl: u32::from_be_bytes([
                            ie_data[13],
                            ie_data[14],
                            ie_data[15],
                            ie_data[16],
                        ]),
                    }
                } else {
                    XnApIe::Unknown {
                        id: ie_id,
                        data: ie_data.to_vec(),
                    }
                }
            }
            30 => XnApIe::UeContextInfoHoReq(ie_data.to_vec()),
            _ => XnApIe::Unknown {
                id: ie_id,
                data: ie_data.to_vec(),
            },
        };

        ies.push(ie);
        data = &data[4 + ie_len..];
    }

    (source_id, target_id, ies)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pfcp_heartbeat() {
        // PFCP v1 Heartbeat Request (no SEID)
        let data: Vec<u8> = vec![
            0x20, // version=1, no SEID flag
            0x01, // Heartbeat Request
            0x00, 0x0c, // length=12
            0x00, 0x00, 0x01, // sequence=1
            0x00, // spare
            // IE: Recovery Timestamp (type=96, len=4, value=1000)
            0x00, 0x60, 0x00, 0x04, 0x00, 0x00, 0x03, 0xE8,
        ];
        let msg = parse_pfcp(&data).unwrap();
        assert_eq!(msg.version, 1);
        assert!(matches!(
            msg.message_type,
            PfcpMessageType::HeartbeatRequest
        ));
        assert_eq!(msg.seid, None);
    }

    #[test]
    fn test_parse_pfcp_session_establishment() {
        // PFCP v1 Session Establishment Request (with SEID)
        let data: Vec<u8> = vec![
            0x21, // version=1, SEID flag set
            0x32, // Session Establishment Request (50)
            0x00, 0x10, // length=16
            // SEID (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, // sequence=2
            0x00, // spare
        ];
        let msg = parse_pfcp(&data).unwrap();
        assert!(matches!(
            msg.message_type,
            PfcpMessageType::SessionEstablishmentRequest
        ));
        assert_eq!(msg.seid, Some(1));
        assert_eq!(msg.sequence_number, 2);
    }

    #[test]
    fn test_parse_pfcp_too_short() {
        let data: Vec<u8> = vec![0x20, 0x01, 0x00];
        assert!(parse_pfcp(&data).is_none());
    }

    #[test]
    fn test_parse_pfcp_wrong_version() {
        let data: Vec<u8> = vec![0x40, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
        assert!(parse_pfcp(&data).is_none());
    }

    #[test]
    fn test_parse_ngap_initial_ue_message() {
        let data: Vec<u8> = vec![
            0x00, // InitiatingMessage
            0x0F, // procedureCode=15 (InitialUEMessage)
            0x00, // criticality=reject
            0x10, // length (placeholder)
            // IE: RAN-UE-NGAP-ID (id=85, len=4)
            0x00, 0x55, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, // IE: NAS-PDU (id=38, len=4)
            0x00, 0x26, 0x00, 0x04, 0x7E, 0x00, 0x41, 0x01,
        ];
        let msg = parse_ngap(&data).unwrap();
        assert!(matches!(
            msg.procedure_code,
            NgapProcedureCode::InitialUEMessage
        ));
        assert!(matches!(
            msg.message_class,
            NgapMessageClass::InitiatingMessage
        ));
        assert_eq!(msg.ran_ue_ngap_id, Some(1));
    }

    #[test]
    fn test_parse_ngap_handover_required() {
        let data: Vec<u8> = vec![
            0x00, // InitiatingMessage
            0x01, // procedureCode=1 (HandoverRequired)
            0x00, // criticality
            0x08, // IE: AMF-UE-NGAP-ID (id=10, len=8)
            0x00, 0x0A, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42,
        ];
        let msg = parse_ngap(&data).unwrap();
        assert!(matches!(
            msg.procedure_code,
            NgapProcedureCode::HandoverRequired
        ));
        assert_eq!(msg.amf_ue_ngap_id, Some(0x42));
    }

    #[test]
    fn test_parse_xnap_handover_preparation() {
        let data: Vec<u8> = vec![
            0x00, // InitiatingMessage
            0x00, // procedureCode=0 (HandoverPreparation)
            0x00, // criticality
            0x08, // IE: source id (id=1, len=4)
            0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0A,
            // IE: target id (id=2, len=4)
            0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0B,
        ];
        let msg = parse_xnap(&data).unwrap();
        assert!(matches!(
            msg.procedure_code,
            XnApProcedureCode::HandoverPreparation
        ));
        assert_eq!(msg.source_ng_ran_node_ue_xnap_id, Some(10));
        assert_eq!(msg.target_ng_ran_node_ue_xnap_id, Some(11));
    }

    #[test]
    fn test_parse_xnap_sn_status_transfer() {
        let data: Vec<u8> = vec![
            0x00, // InitiatingMessage
            0x03, // procedureCode=3 (SNStatusTransfer)
            0x00, // criticality
            0x15, // length
            // IE: SN Status (id=21, len=17)
            0x00, 0x15, 0x00, 0x11, 0x01, // drb_id=1
            0x00, 0x00, 0x00, 0x64, // pdcp_sn_ul=100
            0x00, 0x00, 0x00, 0xC8, // pdcp_sn_dl=200
            0x00, 0x00, 0x00, 0x0A, // hfn_ul=10
            0x00, 0x00, 0x00, 0x14, // hfn_dl=20
        ];
        let msg = parse_xnap(&data).unwrap();
        assert!(matches!(
            msg.procedure_code,
            XnApProcedureCode::SNStatusTransfer
        ));
        assert!(matches!(
            msg.ies.first(),
            Some(XnApIe::SnStatusTransfer {
                drb_id: 1,
                pdcp_sn_ul: 100,
                pdcp_sn_dl: 200,
                ..
            })
        ));
    }

    #[test]
    fn test_parse_ngap_too_short() {
        assert!(parse_ngap(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn test_parse_xnap_too_short() {
        assert!(parse_xnap(&[0x00]).is_none());
    }
}
