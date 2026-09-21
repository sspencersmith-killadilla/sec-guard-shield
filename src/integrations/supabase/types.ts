export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.5"
  }
  public: {
    Tables: {
      attack_techniques: {
        Row: {
          description: string | null
          id: string
          name: string
          revoked: boolean
          synced_at: string
          tactics: string[] | null
          url: string | null
        }
        Insert: {
          description?: string | null
          id: string
          name: string
          revoked?: boolean
          synced_at?: string
          tactics?: string[] | null
          url?: string | null
        }
        Update: {
          description?: string | null
          id?: string
          name?: string
          revoked?: boolean
          synced_at?: string
          tactics?: string[] | null
          url?: string | null
        }
        Relationships: []
      }
      audit_log: {
        Row: {
          action: string
          actor_email: string
          actor_id: string | null
          actor_role: Database["public"]["Enums"]["app_role"] | null
          details: Json
          hash: string
          occurred_at: string
          prev_hash: string
          seq: number
          target: string
        }
        Insert: {
          action: string
          actor_email: string
          actor_id?: string | null
          actor_role?: Database["public"]["Enums"]["app_role"] | null
          details?: Json
          hash: string
          occurred_at?: string
          prev_hash: string
          seq?: number
          target: string
        }
        Update: {
          action?: string
          actor_email?: string
          actor_id?: string | null
          actor_role?: Database["public"]["Enums"]["app_role"] | null
          details?: Json
          hash?: string
          occurred_at?: string
          prev_hash?: string
          seq?: number
          target?: string
        }
        Relationships: []
      }
      cron_config: {
        Row: {
          key: string
          updated_at: string
          value: string
        }
        Insert: {
          key: string
          updated_at?: string
          value: string
        }
        Update: {
          key?: string
          updated_at?: string
          value?: string
        }
        Relationships: []
      }
      epss_scores: {
        Row: {
          cve_id: string
          epss: number
          percentile: number
          score_date: string
          synced_at: string
        }
        Insert: {
          cve_id: string
          epss: number
          percentile: number
          score_date: string
          synced_at?: string
        }
        Update: {
          cve_id?: string
          epss?: number
          percentile?: number
          score_date?: string
          synced_at?: string
        }
        Relationships: []
      }
      feed_sync_runs: {
        Row: {
          error: string | null
          feed_id: string
          finished_at: string | null
          id: string
          latency_ms: number | null
          ok: boolean | null
          records_upserted: number | null
          started_at: string
          trigger: string
        }
        Insert: {
          error?: string | null
          feed_id: string
          finished_at?: string | null
          id?: string
          latency_ms?: number | null
          ok?: boolean | null
          records_upserted?: number | null
          started_at?: string
          trigger?: string
        }
        Update: {
          error?: string | null
          feed_id?: string
          finished_at?: string | null
          id?: string
          latency_ms?: number | null
          ok?: boolean | null
          records_upserted?: number | null
          started_at?: string
          trigger?: string
        }
        Relationships: [
          {
            foreignKeyName: "feed_sync_runs_feed_id_fkey"
            columns: ["feed_id"]
            isOneToOne: false
            referencedRelation: "threat_feeds"
            referencedColumns: ["id"]
          },
        ]
      }
      kev_entries: {
        Row: {
          cve_id: string
          date_added: string | null
          due_date: string | null
          known_ransomware: string | null
          product: string | null
          required_action: string | null
          short_description: string | null
          synced_at: string
          vendor_project: string | null
          vulnerability_name: string | null
        }
        Insert: {
          cve_id: string
          date_added?: string | null
          due_date?: string | null
          known_ransomware?: string | null
          product?: string | null
          required_action?: string | null
          short_description?: string | null
          synced_at?: string
          vendor_project?: string | null
          vulnerability_name?: string | null
        }
        Update: {
          cve_id?: string
          date_added?: string | null
          due_date?: string | null
          known_ransomware?: string | null
          product?: string | null
          required_action?: string | null
          short_description?: string | null
          synced_at?: string
          vendor_project?: string | null
          vulnerability_name?: string | null
        }
        Relationships: []
      }
      nvd_cves: {
        Row: {
          cve_id: string
          cvss_score: number | null
          cvss_severity: string | null
          cvss_vector: string | null
          cvss_version: string | null
          cwe: string | null
          description: string | null
          last_modified: string | null
          published: string | null
          synced_at: string
          vuln_status: string | null
        }
        Insert: {
          cve_id: string
          cvss_score?: number | null
          cvss_severity?: string | null
          cvss_vector?: string | null
          cvss_version?: string | null
          cwe?: string | null
          description?: string | null
          last_modified?: string | null
          published?: string | null
          synced_at?: string
          vuln_status?: string | null
        }
        Update: {
          cve_id?: string
          cvss_score?: number | null
          cvss_severity?: string | null
          cvss_vector?: string | null
          cvss_version?: string | null
          cwe?: string | null
          description?: string | null
          last_modified?: string | null
          published?: string | null
          synced_at?: string
          vuln_status?: string | null
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          email: string
          full_name: string | null
          id: string
        }
        Insert: {
          created_at?: string
          email: string
          full_name?: string | null
          id: string
        }
        Update: {
          created_at?: string
          email?: string
          full_name?: string | null
          id?: string
        }
        Relationships: []
      }
      threat_feeds: {
        Row: {
          auto_update: boolean
          cadence_minutes: number
          dataset_version: string | null
          id: string
          last_error: string | null
          last_synced_at: string | null
          latency_ms: number | null
          name: string
          record_count: number
          source: string
          status: string
          updated_at: string
        }
        Insert: {
          auto_update?: boolean
          cadence_minutes?: number
          dataset_version?: string | null
          id: string
          last_error?: string | null
          last_synced_at?: string | null
          latency_ms?: number | null
          name: string
          record_count?: number
          source: string
          status?: string
          updated_at?: string
        }
        Update: {
          auto_update?: boolean
          cadence_minutes?: number
          dataset_version?: string | null
          id?: string
          last_error?: string | null
          last_synced_at?: string | null
          latency_ms?: number | null
          name?: string
          record_count?: number
          source?: string
          status?: string
          updated_at?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          granted_at: string
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          granted_at?: string
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          granted_at?: string
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      append_audit: {
        Args: { _action: string; _details?: Json; _target: string }
        Returns: number
      }
      bootstrap_profile: {
        Args: { _email: string; _full_name?: string }
        Returns: Database["public"]["Enums"]["app_role"]
      }
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
      verify_audit_chain: {
        Args: never
        Returns: {
          first_broken_seq: number
          total: number
          valid: boolean
        }[]
      }
    }
    Enums: {
      app_role: "admin" | "assessor" | "auditor"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "assessor", "auditor"],
    },
  },
} as const
