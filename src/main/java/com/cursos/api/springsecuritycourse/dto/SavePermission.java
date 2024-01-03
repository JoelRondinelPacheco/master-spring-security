package com.cursos.api.springsecuritycourse.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

public class SavePermission {

    @NotBlank
    private String role;
    @Min(value = 0)
    private String operation;

    public SavePermission() {
    }

    public SavePermission(String role, String operationId) {
        this.role = role;
        this.operation = operationId;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }
}
