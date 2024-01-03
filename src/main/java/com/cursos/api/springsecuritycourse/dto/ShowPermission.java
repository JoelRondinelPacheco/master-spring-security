package com.cursos.api.springsecuritycourse.dto;

public class ShowPermission {
    private long id;
    private String operation;
    private String module;
    private String role;

    public ShowPermission() {
    }

    public ShowPermission(long id, String operation, String module, String role) {
        this.id = id;
        this.operation = operation;
        this.module = module;
        this.role = role;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public String getModule() {
        return module;
    }

    public void setModule(String module) {
        this.module = module;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
